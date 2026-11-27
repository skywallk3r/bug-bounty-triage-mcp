import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { inject } from "@vercel/analytics";

const UA = "bug-bounty-triage-mcp/1.1 (+https://github.com/skywallk3r/bug-bounty-triage-mcp)";

// Initialize Vercel Analytics
inject();

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

const READ_ONLY_LOCAL = { readOnlyHint: true, destructiveHint: false, openWorldHint: false, idempotentHint: true };
const READ_ONLY_WEB = { readOnlyHint: true, destructiveHint: false, openWorldHint: true, idempotentHint: true };

// ---------- Server ----------
function buildServer() {
  const server = new McpServer({ name: "bug-bounty-triage-mcp", version: "1.1.0" });

  server.registerTool(
    "wp_plugin_lookup",
    {
      title: "WordPress Plugin Lookup",
      description: "Look up a WordPress plugin on wordpress.org: current version, active installs, last updated, requirements and rating. Use before hunting a plugin to check freshness and reach. Read-only; queries the public wordpress.org API.",
      inputSchema: { slug: z.string().min(1).describe("Plugin slug, e.g. 'akismet' or 'one-click-order-reorder'") },
      annotations: READ_ONLY_WEB,
    },
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

  server.registerTool(
    "cve_lookup",
    {
      title: "CVE Lookup",
      description: "Search the NVD for recent CVEs matching a product or keyword (e.g. a plugin name). Returns CVE id, published date, description, and CVSS base score when available. Read-only; queries the public NVD API, which can be slow and is keyword-based, so an empty result does not prove no CVE exists.",
      inputSchema: {
        query: z.string().min(2).describe("Keyword search, e.g. 'wordpress apaczka'"),
        max_results: z.number().int().min(1).max(10).default(5),
      },
      annotations: READ_ONLY_WEB,
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

  server.registerTool(
    "cvss_score",
    {
      title: "CVSS Score Calculator",
      description: "Calculate the CVSS 3.1 base score and severity band from a full CVSS vector string. Pure local calculation; no external calls and nothing is stored.",
      inputSchema: { vector: z.string().min(10).describe("e.g. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'") },
      annotations: READ_ONLY_LOCAL,
    },
    async ({ vector }) => {
      const score = cvss31(vector);
      return text({ vector, base_score: score, severity: severityBand(score) });
    }
  );

  server.registerTool(
    "payout_estimate",
    {
      title: "Payout Estimate",
      description: "Estimate an Immunefi-style payout: percent of funds at risk, clamped by the program's minimum and maximum bounty when those bounds are provided. Bounds are optional and independent: if max_usd is omitted the estimate is NOT clamped above and is labelled unbounded_above; if min_usd is omitted it is NOT clamped below and is labelled unbounded_below. When both bounds are provided, min_usd must not exceed max_usd — otherwise the tool returns a clear error instead of an estimate. Pure local calculation; the result is only as good as the funds/percent/bounds supplied.",
      inputSchema: {
        funds_at_risk_usd: z.number().nonnegative().describe("Funds at risk in USD that the percent applies to"),
        percent: z.number().min(0).max(100).describe("Percent of funds at risk paid for this severity, e.g. 10 for Critical on many programs"),
        max_usd: z.number().nonnegative().optional().describe("Program maximum bounty cap in USD. Optional: omit for no upper clamp (estimate labelled unbounded_above). Must be >= min_usd when both are given."),
        min_usd: z.number().nonnegative().optional().describe("Program minimum payout in USD. Optional: omit for no lower clamp (estimate labelled unbounded_below). Must be <= max_usd when both are given."),
      },
      annotations: READ_ONLY_LOCAL,
    },
    async ({ funds_at_risk_usd, percent, max_usd, min_usd }) => {
      if (min_usd !== undefined && max_usd !== undefined && min_usd > max_usd) {
        throw new Error(`Invalid bounds: min_usd ($${min_usd}) must not exceed max_usd ($${max_usd}). Fix the program's minimum/maximum bounty values and try again.`);
      }
      let estimate = (funds_at_risk_usd * percent) / 100;
      let clampedBy = null;
      if (max_usd !== undefined && estimate > max_usd) { estimate = max_usd; clampedBy = "max"; }
      if (min_usd !== undefined && estimate < min_usd) { estimate = min_usd; clampedBy = "min"; }
      const unbounded = [];
      if (max_usd === undefined) unbounded.push("above — no maximum bounty provided, so no upper clamp was applied");
      if (min_usd === undefined) unbounded.push("below — no minimum payout provided, so no lower clamp was applied");
      return text({
        funds_at_risk_usd,
        percent,
        raw_percent_value_usd: Math.round((funds_at_risk_usd * percent) / 100),
        estimate_usd: Math.round(estimate),
        clamped_by: clampedBy,
        bounds_applied: { min_usd: min_usd ?? null, max_usd: max_usd ?? null },
        unbounded: unbounded.length ? unbounded : null,
      });
    }
  );

  server.registerTool(
    "program_vet",
    {
      title: "Program Vet",
      description: "Quick-vet a bug bounty program against common deal-breakers, using ONLY the facts you supply. Important: every field except the program name is optional, and an omitted field is treated as UNKNOWN — it is never assumed to be false, zero, or favourable. The verdict lists which facts were confirmed and which are unknown, and is marked provisional when decision-critical facts are missing. Criteria: a confirmed blocked level gate forces a 'Park it' verdict on its own; pay-to-submit above $0 is flagged at its stated per-report cost; KYC and a PoC requirement are flagged as friction; TVL under $1,000,000 is flagged 'low TVL'; a maximum bounty under $10,000 is flagged 'low ceiling'. Three or more flags give a 'Cautious' verdict. This tool verifies nothing itself and submits nothing — supply facts from the program page for a grounded verdict.",
      inputSchema: {
        name: z.string().min(1).describe("Program name"),
        level_gate_blocked: z.boolean().optional().describe("True only if your researcher level is CONFIRMED blocked on this program. Omit if unknown — it will be reported as unknown, not assumed unblocked."),
        pay_to_submit_usd: z.number().nonnegative().optional().describe("Per-report submission fee in USD, if the program charges one. Omit if unknown; provide 0 only if you confirmed there is no fee."),
        kyc_required: z.boolean().optional().describe("True if KYC is required to get paid. Omit if unknown."),
        poc_required: z.boolean().optional().describe("True if a working proof of concept is required. Omit if unknown."),
        max_bounty_usd: z.number().nonnegative().optional().describe("Program maximum bounty in USD. Omit if unknown — the ceiling will not be judged."),
        tvl_usd: z.number().nonnegative().optional().describe("Total value locked / funds in scope in USD. Omit if unknown — TVL will not be judged."),
      },
      annotations: READ_ONLY_LOCAL,
    },
    async ({ name, level_gate_blocked, pay_to_submit_usd, kyc_required, poc_required, max_bounty_usd, tvl_usd }) => {
      const flags = [];
      const unknown = [];
      if (level_gate_blocked === undefined) unknown.push("level_gate_blocked — whether your level is gated is unknown (not assumed unblocked)");
      else if (level_gate_blocked) flags.push("BLOCKED: your researcher level is gated out of this program (confirmed).");
      if (pay_to_submit_usd === undefined) unknown.push("pay_to_submit_usd — submission fee unknown (not assumed free)");
      else if (pay_to_submit_usd > 0) flags.push(`Pay-to-submit is on: $${pay_to_submit_usd} per report (confirmed).`);
      if (kyc_required === undefined) unknown.push("kyc_required — KYC requirement unknown");
      else if (kyc_required) flags.push("KYC required to get paid (confirmed).");
      if (poc_required === undefined) unknown.push("poc_required — PoC requirement unknown");
      else if (poc_required) flags.push("Working PoC required — nothing counts without one (confirmed).");
      if (tvl_usd === undefined) unknown.push("tvl_usd — TVL not provided, so percent-of-funds value was not judged");
      else if (tvl_usd < 1000000) flags.push(`Low TVL: $${tvl_usd.toLocaleString()} (under the $1,000,000 threshold) — percent-of-funds payouts will be small.`);
      if (max_bounty_usd === undefined) unknown.push("max_bounty_usd — bounty ceiling not provided, so it was not judged");
      else if (max_bounty_usd < 10000) flags.push(`Low ceiling: max bounty $${max_bounty_usd.toLocaleString()} (under the $10,000 threshold).`);

      let verdict;
      if (level_gate_blocked === true) verdict = "Park it — level gate blocks you (confirmed).";
      else if (level_gate_blocked === undefined) verdict = "Provisional — the level-gate status was not provided, and that is the one fact that can block you outright. Confirm it before relying on this verdict.";
      else if (flags.length >= 3) verdict = "Cautious — several confirmed friction points.";
      else verdict = "Worth a look — based only on the confirmed facts supplied.";
      if (level_gate_blocked === true && unknown.length) verdict += ` Note: ${unknown.length} other fact(s) are still unknown.`;
      else if (level_gate_blocked === false && unknown.length) verdict += ` Provisional: ${unknown.length} fact(s) unknown.`;

      return text({
        program: name,
        verdict,
        flags,
        flag_count: flags.length,
        unknown_facts: unknown,
        assumptions: "None. Omitted facts are treated as unknown, never as false, zero, or favourable.",
        criteria: { low_tvl_threshold_usd: 1000000, low_ceiling_threshold_usd: 10000, cautious_flag_count: 3 },
      });
    }
  );

  return server;
}

const app = express();
app.use(express.json());

app.get("/", (req, res) => {
  // Serve HTML with analytics for browsers, JSON for API clients
  if (req.accepts("html") && !req.accepts("json")) {
    res.type("html").send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Bug Bounty Triage MCP</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      max-width: 800px;
      margin: 2rem auto;
      padding: 0 1rem;
      line-height: 1.6;
      color: #333;
    }
    h1 { color: #000; }
    code {
      background: #f4f4f4;
      padding: 0.2rem 0.4rem;
      border-radius: 3px;
      font-size: 0.9em;
    }
    .endpoint {
      background: #f8f9fa;
      border-left: 3px solid #0070f3;
      padding: 1rem;
      margin: 1rem 0;
    }
    ul { padding-left: 1.5rem; }
  </style>
  <script>
    window.va = window.va || function () { (window.vaq = window.vaq || []).push(arguments); };
  </script>
  <script defer src="/_vercel/insights/script.js"></script>
</head>
<body>
  <h1>Bug Bounty Triage MCP</h1>
  <p>An MCP server for bug bounty triage. Stateless, no database, no API keys needed.</p>
  
  <h2>Tools</h2>
  <ul>
    <li><strong>wp_plugin_lookup</strong> — WordPress plugin version, active installs, last updated, requirements and rating from wordpress.org.</li>
    <li><strong>cve_lookup</strong> — Search the NVD for CVEs matching a product/keyword, with CVSS scores when available.</li>
    <li><strong>cvss_score</strong> — CVSS 3.1 base score + severity band from a vector string.</li>
    <li><strong>payout_estimate</strong> — Percent-of-funds-at-risk payout estimate, clamped by a program's min/max.</li>
    <li><strong>program_vet</strong> — Quick-vet a program for deal-breakers: level gate, pay-to-submit, KYC, PoC required, low TVL, low ceiling.</li>
  </ul>

  <h2>Endpoints</h2>
  <div class="endpoint">
    <strong>POST /mcp</strong><br>
    MCP protocol endpoint for tool execution
  </div>
  <div class="endpoint">
    <strong>GET /health</strong><br>
    Health check endpoint
  </div>

  <p>
    <a href="https://github.com/skywallk3r/bug-bounty-triage-mcp" target="_blank">View on GitHub</a>
  </p>
</body>
</html>`);
  } else {
    res.json({ ok: true, name: "bug-bounty-triage-mcp", version: "1.1.0", tools: ["wp_plugin_lookup", "cve_lookup", "cvss_score", "payout_estimate", "program_vet"] });
  }
});
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
