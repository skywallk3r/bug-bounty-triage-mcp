import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const UA = "bug-bounty-triage-mcp/1.0 (+https://github.com/skywallk3r/bug-bounty-triage-mcp)";

async function fetchJson(url, timeoutMs = 15000) {
  const res = await fetch(url, {
    headers: { "User-Agent": UA, Accept: "application/json" },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${new URL(url).hostname}`);
  return res.json();
}

function text(obj) {
  return { content: [{ type: "text", text: typeof obj === "string" ? obj : JSON.stringify(obj, null, 2) }] };
}

// ---------- CVSS 3.1 base score ----------
const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC = { L: 0.77, H: 0.44 };
const UI = { N: 0.85, R: 0.62 };
const CIA = { N: 0, L: 0.22, H: 0.56 };
function prValue(pr, scope) {
  if (pr === "N") return 0.85;
  if (scope === "U") return pr === "L" ? 0.62 : 0.27;
  return pr === "L" ? 0.68 : 0.5;
}
function roundUp(input) {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}
function cvss31(vector) {
  const v = vector.trim().replace(/^CVSS:3\.[01]\//, "");
  const m = {};
  for (const part of v.split("/")) {
    const [k, val] = part.split(":");
    if (k && val) m[k.toUpperCase()] = val.toUpperCase();
  }
  for (const k of ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]) {
    if (!(k in m)) throw new Error(`Missing metric ${k} in vector`);
  }
  const scope = m.S;
  const iss = 1 - (1 - CIA[m.C]) * (1 - CIA[m.I]) * (1 - CIA[m.A]);
  let impact;
  if (scope === "U") impact = 6.42 * iss;
  else impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  const exploitability = 8.22 * AV[m.AV] * AC[m.AC] * prValue(m.PR, scope) * UI[m.UI];
  if (impact <= 0) return 0;
  const raw = scope === "U" ? Math.min(impact + exploitability, 10) : Math.min(1.08 * (impact + exploitability), 10);
  return roundUp(raw);
}
function severityBand(score) {
  if (score === 0) return "None";
  if (score < 4) return "Low";
  if (score < 7) return "Medium";
  if (score < 9) return "High";
  return "Critical";
}

// ---------- Server ----------
function buildServer() {
  const server = new McpServer({ name: "bug-bounty-triage-mcp", version: "1.0.0" });

  server.tool(
    "wp_plugin_lookup",
    "Look up a WordPress plugin on wordpress.org: current version, active installs, last updated, requirements and rating. Use before hunting a plugin to check freshness and reach.",
    { slug: z.string().min(1).describe("Plugin slug, e.g. 'akismet' or 'one-click-order-reorder'") },
    async ({ slug }) => {
      const clean = slug.trim().toLowerCase().replace(/[^a-z0-9-_]/g, "");
      const url = `https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=${encodeURIComponent(clean)}&request[fields][sections]=0&request[fields][versions]=0`;
      const data = await fetchJson(url);
      if (!data || data.error || !data.name) return text({ found: false, slug: clean, note: "No plugin with that slug on wordpress.org." });
      return text({
        found: true,
        name: data.name,
        slug: data.slug,
        version: data.version,
        active_installs: data.active_installs,
        last_updated: data.last_updated,
        added: data.added,
        requires_wordpress: data.requires,
        tested_up_to: data.tested,
        requires_php: data.requires_php,
        rating_percent: data.rating,
        num_ratings: data.num_ratings,
        downloaded: data.downloaded,
        download_link: data.download_link,
        homepage: data.homepage || undefined,
      });
    }
  );

  server.tool(
    "cve_lookup",
    "Search the NVD for recent CVEs matching a product or keyword (e.g. a plugin name). Returns CVE id, published date, description, and CVSS base score when available.",
    {
      query: z.string().min(2).describe("Keyword search, e.g. 'wordpress apaczka'"),
      max_results: z.number().int().min(1).max(10).default(5),
    },
    async ({ query, max_results }) => {
      const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=${max_results}`;
      const data = await fetchJson(url, 25000);
      const vulns = (data.vulnerabilities || []).map(({ cve }) => {
        const desc = (cve.descriptions || []).find((d) => d.lang === "en")?.value || "";
        const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
        return {
          id: cve.id,
          published: cve.published,
          last_modified: cve.lastModified,
          status: cve.vulnStatus,
          description: desc.slice(0, 600),
          cvss: metrics ? { score: metrics.cvssData.baseScore, severity: metrics.cvssData.baseSeverity || metrics.baseSeverity, vector: metrics.cvssData.vectorString } : undefined,
        };
      });
      return text({ query, total_results: data.totalResults ?? vulns.length, returned: vulns.length, cves: vulns });
    }
  );

  server.tool(
    "cvss_score",
    "Calculate the CVSS 3.1 base score and severity band from a full CVSS vector string.",
    { vector: z.string().min(10).describe("e.g. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'") },
    async ({ vector }) => {
      const score = cvss31(vector);
      return text({ vector, base_score: score, severity: severityBand(score) });
    }
  );

  server.tool(
    "payout_estimate",
    "Estimate an Immunefi-style payout: percent of funds at risk, clamped by the program's minimum and maximum bounty.",
    {
      funds_at_risk_usd: z.number().nonnegative(),
      percent: z.number().min(0).max(100).describe("Percent of funds at risk paid for this severity, e.g. 10 for Critical on many programs"),
      max_usd: z.number().nonnegative().optional().describe("Program maximum bounty cap in USD"),
      min_usd: z.number().nonnegative().optional().describe("Program minimum payout in USD"),
    },
    async ({ funds_at_risk_usd, percent, max_usd, min_usd }) => {
      let estimate = (funds_at_risk_usd * percent) / 100;
      let clampedBy = null;
      if (max_usd !== undefined && estimate > max_usd) { estimate = max_usd; clampedBy = "max"; }
      if (min_usd !== undefined && estimate < min_usd) { estimate = min_usd; clampedBy = "min"; }
      return text({
        funds_at_risk_usd,
        percent,
        raw_percent_value_usd: Math.round((funds_at_risk_usd * percent) / 100),
        estimate_usd: Math.round(estimate),
        clamped_by: clampedBy,
      });
    }
  );

  server.tool(
    "program_vet",
    "Quick-vet a bug bounty program against common deal-breakers: blocked researcher level, pay-to-submit fees, KYC, PoC requirement, low TVL or a low bounty ceiling. Returns flags and a park / look verdict. It does not submit anything.",
    {
      name: z.string().min(1),
      level_gate_blocked: z.boolean().default(false).describe("True if your researcher level is blocked on this program"),
      pay_to_submit_usd: z.number().nonnegative().default(0),
      kyc_required: z.boolean().default(false),
      poc_required: z.boolean().default(true),
      max_bounty_usd: z.number().nonnegative().optional(),
      tvl_usd: z.number().nonnegative().optional(),
    },
    async ({ name, level_gate_blocked, pay_to_submit_usd, kyc_required, poc_required, max_bounty_usd, tvl_usd }) => {
      const flags = [];
      if (level_gate_blocked) flags.push("BLOCKED: your researcher level is gated out of this program.");
      if (pay_to_submit_usd > 0) flags.push(`Pay-to-submit is on: $${pay_to_submit_usd} per report.`);
      if (kyc_required) flags.push("KYC required to get paid.");
      if (poc_required) flags.push("Working PoC required — nothing counts without one.");
      if (tvl_usd !== undefined && tvl_usd < 1000000) flags.push(`Low TVL: $${tvl_usd.toLocaleString()} — percent-of-funds payouts will be small.`);
      if (max_bounty_usd !== undefined && max_bounty_usd < 10000) flags.push(`Low ceiling: max bounty $${max_bounty_usd.toLocaleString()}.`);
      const verdict = level_gate_blocked ? "Park it — level gate blocks you." : flags.length >= 3 ? "Cautious — several friction points." : "Worth a look.";
      return text({ program: name, verdict, flags, flag_count: flags.length });
    }
  );

  return server;
}

const app = express();
app.use(express.json());

app.get("/", (_req, res) => res.json({ ok: true, name: "bug-bounty-triage-mcp", tools: ["wp_plugin_lookup", "cve_lookup", "cvss_score", "payout_estimate", "program_vet"] }));
app.get("/health", (_req, res) => res.json({ ok: true }));

app.post("/mcp", async (req, res) => {
  const server = buildServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => { transport.close(); server.close(); });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: String(err?.message || err) }, id: null });
  }
});
app.get("/mcp", (_req, res) => res.status(405).json({ error: "Method not allowed — use POST" }));
app.delete("/mcp", (_req, res) => res.status(405).json({ error: "Method not allowed" }));

const port = Number(process.env.PORT || 3000);
app.listen(port, "0.0.0.0", () => console.log(`bug-bounty-triage-mcp listening on port ${port}`));
