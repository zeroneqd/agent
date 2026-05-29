# Threat Translator — Core Reference

> **Loaded by:** `detection-helper.agent.md` (Path A — threat intel decomposition).
> **Purpose:** Threat parsing, primitive mapping, coverage matrix format, gap analysis.

## Workflow (5 steps)

### Step 1: EXTRACT

For CVE: fetch from `nvd.nist.gov`, `cvedetails.com`, `api.first.org/data/v1/epss`
For threat URL: parse article for affected product, exploitation technique, post-exploitation behavior

Extract fields:
```yaml
cve_id: "CVE-YYYY-NNNNN"
product: "Vendor Product"
affected_versions: "X.Y - A.B"
vulnerability_type: "RCE / LPE / Deserialization / etc."
attack_vector: "Network / Local / etc."
privileges_required: "None / Low / High"
epss_score: 0.00-1.00
kev_listed: true/false
```

### Step 2: BEHAVIORAL ANALYSIS

Using `docs/threat-intel/operation-taxonomy.md` and `docs/threat-intel/cve-decomposer.md`:
1. Identify vulnerability type
2. Look up type → primitives mapping
3. List primary, secondary, and optional primitives

### Step 3: TELEMETRY MAPPING

For each primitive:
1. Search `docs/index/telemetry-index.json` keywords array
2. Confirm table, ActionType, columns
3. Check `docs/schema-overview.md` Gaps
4. Check `docs/tenant/all-actiontypes.md` for tenant observation

### Step 4: GAP ANALYSIS

🟢 Confirmed — documented + observed, no known gap → proceed
🟡 Partial — documented with known gaps → include with caveat
🔴 Not logged — no telemetry → propose mitigation

### Step 5: DETECTION PLAN

Priority order: (kill_chain_position × fidelity) / fp_risk
1. Earliest confirmed primitive
2. Highest fidelity primitive
3. Outcome primitives (fallback)

## Search strategy (max 3 `search/codebase` + 2 `web/fetch`)

1. Threat intel docs — `docs/threat-intel/operation-taxonomy.md`, `cve-decomposer.md`
2. Telemetry index — `docs/index/telemetry-index.json`
3. Schema gaps — `docs/schema-overview.md`
4. Detection patterns — `docs/detection-patterns/` / `docs/detection-fragments/`
5. Tenant data — `docs/tenant/all-actiontypes.md`

## Confidence notation (L1-L5)

Use `docs/agent-ref/shared-confidence.md`. Threat-translator typical levels:
- L3: Schema-confirmed (from index + schema)
- L2: Documented in public docs
- L1: Inferred from vulnerability type → primitive mapping

**Never claim L4/L5** — tenant verification is the telemetry agent's job.

## Session state write

After Step 3, append Phase 1 to `docs/session/state.md` with all primitives
their mappings, gaps, and detection priority order.

## EPSS + KEV prioritization

| EPSS | KEV | Priority | Response |
|---|---|---|---|
| > 0.5 | Yes | Critical | Full pipeline immediately |
| > 0.5 | No | High | Full pipeline, note no KEV |
| 0.1-0.5 | Yes | High | Full pipeline |
| 0.1-0.5 | No | Medium | Standard pipeline |
| < 0.1 | Yes | Medium | Standard pipeline |
| < 0.1 | No | Low | Decompose but deprioritize vs active threats |

## Rules of engagement

- **Behavior over IOCs.** Never propose purely IOC-based detection without behavioral.
- **Never invent telemetry.** Check index before claiming coverage.
- **Always provide gap analysis.** Note every blind spot.
- **Kill-chain order matters.** Detect early, fallback to late.
