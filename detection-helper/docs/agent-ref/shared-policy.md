# Shared Agent Policy

> **Purpose.** Grounding rules, memory protocol, and scope boundaries shared by
all paths. Reference this file instead of duplicating in the agent prompt.

## Grounding rules (all paths)

- **Never invent telemetry.** Column names, ActionTypes, Event IDs must be
  confirmed via `tools.telemetry` before use. L3 (Schema-Confirmed) minimum for
  columns in queries.
- **Never write rules for unlogged events.** If `tools.telemetry` says
  "not logged," propose verification rather than writing a blind rule.
- **Always check anti-patterns.** `tools.telemetry.validate_columns()` runs
  this automatically — trust its output.
- **Confidence is L1-L5 only.** Use `tools.confidence` for calculation. Never
  use per-agent "confirmed/documented/inferred" — those terms are retired.
- **Coverage validator required.** Every factual claim about telemetry must
  include a validation query when confidence is below L4.

## Memory protocol (all agents)

- **Repository scope only** for durable preferences (answer format, default SIEM,
  environment facts like "no Sysmon deployed").
- **Facts go to version-controlled files:** `docs/notes/` for telemetry findings,
  `docs/detection-patterns/` or `docs/detection-fragments/` for detection logic.
- **Never use GitHub-hosted Copilot Memory.** All retained context is local.
- **Never store in session memory tool.** Factual detection knowledge needs
  provenance (date + source) and review.

## Out of scope (all agents)

- No production rule deployment (no API calls to Defender/Splunk)
- No organizational SOC process or team boundary commentary
- No Sigma/YARA-L unless explicitly requested
- No non-Microsoft/Splunk platforms unless explicitly requested

## Confidence defaults by agent

| Agent | Typical max | When to require L5 |
|---|---|---|
| Router | N/A (no factual claims) | N/A |
| Threat Translator | L3 (Schema-Confirmed) | Before declaring "no gap" |
| Defender Telemetry | L4 (Tenant-Observed) | When tenant data > 14 days old |
| Detection Author | L3 (Schema-Confirmed) | Before using column in production query |
