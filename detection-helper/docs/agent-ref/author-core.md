# Detection Author — Core Reference

> **Loaded by:** `detection-helper.agent.md` (Path C — detection authoring).
> **Purpose:** Rule construction standards, pattern selection, quality scoring.

## Workflow (4 phases)

### Phase 1: Requirement analysis

1. Parse detection requirement: target behavior, platform, SIEM, MITRE technique, constraints
2. **Verify telemetry exists** — read `docs/session/state.md` if available, or search
   `docs/index/telemetry-index.json` for table/ActionType/column confirmation
3. If telemetry is Unknown or gap-prone → STOP, propose verification approach
4. Map to MITRE ATT&CK if user didn't specify

### Phase 2: Pattern selection

1. Search `docs/detection-patterns/` and `docs/detection-fragments/` for matches
2. Check `docs/detection-fragments/primitives/` for primitive-specific fragments
3. Check `docs/detection-fragments/combinators/` for multi-primitive composition
4. If no exact match: combine fragments or write from scratch

### Phase 3: Rule construction

**KQL standards:**
- Lowercase operators on new lines after `|`
- Double-quoted string literals
- `has` over `contains` on high-cardinality columns
- Filter before join, `project` early
- ≤ 40 lines unless complexity demands more

**SPL standards:**
- `index=` first, filter early, `stats` efficiently
- `where` for compound conditions
- Proper Windows event XML extraction

### Phase 4: Quality assurance (MANDATORY)

1. **Run Cross-Agent Validation Gate** — `docs/agent-ref/shared-validation.md`
   - Read session state, cross-check every table/ActionType/column
   - Any mismatch → STOP and flag
2. **Score the rule:**

| Dimension | Score | Notes |
|---|---|---|
| Coverage | high/medium/low | How much of technique does this catch? |
| FP risk | low/medium/high | Expected noise level |
| Performance | fast/moderate/slow | Query execution cost |
| Blind spots | list | Known evasions or gaps |
| MITRE | technique+sub | Mapped ATT&CK IDs |

3. **Add FP guidance:** expected noise, baseline query, exclusions, thresholds
4. **Add test plan:** benign test, malicious simulation, volume estimate

## Search strategy (max 3 `search/codebase` calls)

1. **Pattern lookup** — `docs/detection-patterns/` + `docs/detection-fragments/`
2. **Index lookup** — `docs/index/telemetry-index.json` — table/column confirmation
3. **Schema confirmation** — `docs/advanced-hunting/<table>-table.md`

After 3 calls, propose rule with caveats.

## Confidence notation (L1-L5)

Use `docs/agent-ref/shared-confidence.md`. Detection-author typical levels:
- L3: Schema-confirmed columns used in query
- L4: Pattern validated in tenant (from `all-actiontypes.md`)
- L5: Includes live validation query

**Rule confidence = minimum confidence of all elements.**
If columns are L3 and ActionType is L4 → rule is L3.

## Rules of engagement

- **Never invent telemetry.** Verify through corpus before writing.
- **Never write rules for unlogged events.** Propose fallback or verification.
- **Always provide both KQL and SPL when possible.**
- **Always include FP guidance + test plan.**
- **Prefer technique-scoped over tool-scoped rules.**
- **Performance matters.** Note expensive operations.

## Out of scope

- No API deployment to Defender/Splunk
- No Sigma/YARA-L unless explicitly requested
- No non-Microsoft/Splunk platforms unless explicitly requested
- No organizational SOC process commentary
