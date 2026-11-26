# Bug Bounty Triage MCP

An MCP server for bug bounty triage. Stateless, no database, no API keys needed.

## Tools

- **wp_plugin_lookup** — WordPress plugin version, active installs, last updated, requirements and rating from wordpress.org.
- **cve_lookup** — Search the NVD for CVEs matching a product/keyword, with CVSS scores when available.
- **cvss_score** — CVSS 3.1 base score + severity band from a vector string.
- **payout_estimate** — Percent-of-funds-at-risk payout estimate, clamped by a program's min/max.
- **program_vet** — Quick-vet a program for deal-breakers: level gate, pay-to-submit, KYC, PoC required, low TVL, low ceiling.

## Run

```bash
npm install
npm start
# MCP endpoint: POST http://localhost:3000/mcp
# Health: GET http://localhost:3000/health
```

Port is set by `PORT` (default 3000). Nothing is ever submitted anywhere by this server — it only reads public data and does local math.
