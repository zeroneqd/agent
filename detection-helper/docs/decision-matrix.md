# Decision Matrix — Quick-Start Routing Table

> **Purpose.** Eliminate reasoning rounds by mapping common query patterns directly
to starting files. Load this file on every request to shortlist candidates before
drilling into per-table references.

## How to use this file

1. Match the user's question to the closest row in the **Query Pattern** column.
2. Open the **Start Here** file first.
3. Follow the **Fallback Chain** only if the primary file doesn't answer the question.
4. Confirm all column names and ActionTypes against `docs/advanced-hunting/*.md`
before responding — this file is a routing aid, not authoritative for schema.

-----

## Primary routing table

| Query Pattern | Start Here | Fallback Chain | Question Type |
|---|---|---|---|
| "Is X logged in Defender?" | `docs/schema-overview.md` → table file | `docs/tenant/actiontypes/` → `docs/index/telemetry-index.json` | MDE-scoped |
| "How do I hunt X in Sentinel / Splunk / Sysmon?" | `docs/windows-events/` | `docs/schema-overview.md` for MDE equivalent | Cross-SIEM |
| "MDE doesn't show X, where else is it logged?" | Check Gaps in `schema-overview.md` → `docs/windows-events/sysmon-events.md` | `docs/windows-events/powershell-operational.md` → conclude "not logged" | Gap-driven |
| "Which ActionType for...?" | `docs/tenant/actiontypes/` | `docs/index/telemetry-index.json` → `docs/advanced-hunting/` | ActionType lookup |
| "Linux coverage for...?" | `docs/tenant/DeviceEvents-by-platform.md` | `schema-overview.md` Linux section | Platform-scoped |
| "What's the column name for...?" | `docs/advanced-hunting/<table>-table.md` | `docs/index/telemetry-index.json` columns list | Schema lookup |
| "Translate this MDE hunt to Sentinel/Splunk" | `docs/windows-events/defender-to-eventid-mapping.md` | `docs/advanced-hunting/` for column confirmation | Cross-SIEM |
| "Is this PowerShell activity logged?" | `docs/windows-events/powershell-operational.md` | `docs/advanced-hunting-deviceevents-table.md` | PowerShell-scoped |
| "Email / phishing question" | `docs/schema-overview.md` MDO section | `docs/advanced-hunting-emailevents-table.md` | MDO-scoped |
| "Identity / AD / Entra question" | `docs/schema-overview.md` MDI/Entra section | `docs/advanced-hunting-identity*.md` | Identity-scoped |
| "Vulnerability / exposure question" | `docs/schema-overview.md` TVM section | `docs/advanced-hunting-devicetvm*.md` | TVM-scoped |
| "Alert / investigation question" | `docs/advanced-hunting-alertinfo-table.md` | `docs/advanced-hunting-alertevidence-table.md` | Alert-scoped |
| "SaaS / cloud app question" | `docs/advanced-hunting-cloudappevents-table.md` | `docs/advanced-hunting-aadsignineventsbeta-table.md` | MDCA-scoped |
| "AI agent / MCP question" | `docs/advanced-hunting-cloudappevents-table.md` | `docs/schema-overview.md` AI agent section | Agent-scoped |

-----

## Confidence shortcuts

When you can answer without file access, do so — but mark confidence accordingly:

| Scenario | Confidence | Action |
|---|---|---|
| Table + ActionType confirmed in `telemetry-index.json` + tenant data present | **Confirmed** | Answer directly; still validate columns in per-table md |
| Table + ActionType in `telemetry-index.json` but NOT in tenant data | **Documented-only** | Answer with caveat: "Documented but not observed in tenant over <lookback>" |
| Table + ActionType not in `telemetry-index.json` but in `schema-overview.md` | **Documented-only** | Answer with caveat; propose verification query |
| Inferred from confirmed data but no direct source | **Inferred** | Flag "Inferred from <basis> — verify before deploying" |
| No source covers this | **Unknown** | Return "Not confirmed" with proposed verification approach |

-----

## Search strategy (use instead of broad keyword search)

Follow this order to minimize `search/codebase` calls:

1. **Exact table name match** — `search/codebase "DeviceProcessEvents"` — most specific
2. **Exact ActionType match** — `search/codebase "ProcessCreated"` — exact string
3. **Index lookup** — read `docs/index/telemetry-index.json`, search the `keywords` array
4. **Schema overview** — read `docs/schema-overview.md` and scan the quick scenario table
5. **Decision matrix** — this file, for question-type routing

**Never** search for generic terms like "event", "log", "activity", or "telemetry" —
these return too many matches. Use the index or schema overview instead.

**Limit:** Maximum 2-3 `search/codebase` calls per query. If not found after 3 calls,
use `docs/schema-overview.md` as the authoritative index.

-----

## Platform routing

| Platform | Primary tables | Key caveats |
|---|---|---|
| Windows (default) | All device tables | Full coverage; some prerequisites apply |
| Linux | `DeviceProcessEvents`, `DeviceFileEvents` (partial), `DeviceNetworkEvents` (partial), `DeviceEvents` (`KernelModuleLoad`, `BpfFilterAttached`, `PTraceDetected`) | See `schema-overview.md` Linux section — default to "partial" |
| macOS | `DeviceProcessEvents` (partial), `DeviceFileEvents` (partial), `DeviceNetworkEvents` (partial) | Narrower than Linux; many ActionTypes absent |
| Email / cloud | `EmailEvents`, `CloudAppEvents`, `AADSignInEventsBeta` | Workload dependencies: MDO, MDCA, Entra connector |

-----

*Last updated: 2026-05-28. Keep in sync with `schema-overview.md` and `telemetry-index.json`.*
