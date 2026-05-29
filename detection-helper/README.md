# Detection Helper

A detection-engineering assistant for Microsoft Defender / Sentinel and Splunk.
It turns threat intel (CVEs, reports, URLs) and plain-language questions into
grounded telemetry answers and production KQL/SPL detection rules.

The design is a **single agent over deterministic Python tools**: the agent
(an LLM) handles judgment — threat parsing, false-positive analysis, gap
assessment — while every fact it relies on (tables, columns, ActionTypes,
primitives, confidence) comes from the tools in `tools/`. The agent never
invents telemetry; it verifies first.

## Architecture

```
                ┌─────────────────────────────┐
 user message → │  detection-helper.agent.md  │  (the only agent)
                └──────────────┬──────────────┘
                               │ Step 0: tools.router gives an advisory hint
          ┌────────────┬───────┴────────┬─────────────┐
          ▼            ▼                ▼             ▼
      Path A       Path B            Path C        Path D
   threat intel   telemetry        detection      clarify
   decomposition  lookup           authoring     (last resort)
          │            │                │
          └────────────┴────────────────┘
        session state (docs/session/state.json) threads phases together
```

There is **no agent-to-agent handoff** (the VS Code custom-agent format doesn't
support it). The one agent both chooses the path and executes it in the same
turn. The four older agents (`router`, `defender-telemetry`, `detection-author`,
`threat-translator`) were consolidated into this one.

### Paths

- **A — Threat intel.** Decompose a CVE/report/URL into exploit primitives
  (P1–P12), build a coverage matrix and gap analysis, and (unless stopped early)
  continue into B and C as a pipeline.
- **B — Telemetry lookup.** "Is action X on OS Y logged, where, which columns,
  which ActionType?" Answered from the schema/tenant data with a confidence
  level and a coverage-validator query.
- **C — Detection authoring.** Compose and customize KQL/SPL rules, then run a
  mandatory cross-phase validation gate before finalizing.
- **D — Clarify.** Reserved for input with no actionable content ("help", "hi").
  Anything naming a concrete behavior is assumed-and-proceeded instead.

### Command prefixes

Routing is advisory by default, but a leading `verb:` is **authoritative** and
overrides every heuristic:

| Prefix | Path | Behavior |
|---|---|---|
| `intel:` / `threat:` | A only | Decompose + gaps, stop at the plan |
| `event:` / `telemetry:` | B | Telemetry lookup only |
| `rule:` / `detect:` | B → C | Verify telemetry, then author + validate |
| `pipeline:` / `full:` | A → B → C | Full chain end-to-end |

## Tools

All deterministic logic lives in `tools/` and is invokable as a module CLI
(`python -m tools.<name>`). Runtime tools depend only on the Python standard
library.

| Module | Responsibility |
|---|---|
| `router` | Advisory path selection + command-prefix override |
| `telemetry` | Resolve actions → tables/columns/ActionTypes; validate columns |
| `primitives` | Exploit-primitive registry (P1–P12), kill-chain ordering |
| `patterns` | `PatternComposer` — assemble rules from fragments/combinators |
| `validator` | Cross-phase validation gate (table/action/columns/primitive/confidence) |
| `confidence` | L1–L5 confidence ontology and scoring |
| `session` | JSON pipeline state machine threading A→B→C |
| `health` | Startup/self-check CLI |
| `metrics` | Lightweight query/token logging |

## Repository layout

```
.github/agents/detection-helper.agent.md   the agent prompt
.github/workflows/                          tests + weekly schema-sync
tools/                                       deterministic Python tools
tests/                                       pytest suite
docs/advanced-hunting/                       Defender table schemas
docs/detection-fragments/, detection-patterns/   reusable KQL building blocks
docs/agent-ref/                              path reference material (loaded by the agent)
docs/threat-intel/                           primitive taxonomy + CVE decomposer
docs/tenant/                                 tenant-observed ActionTypes + freshness
docs/session/state.json                      runtime pipeline state (git-ignored)
```

## Development

```bash
pip install -r requirements-dev.txt
pytest -q
```

Tests run automatically on push and pull request (`.github/workflows/tests.yml`).
A separate weekly workflow (`schema-sync.yml`) checks the local Defender schema
copies against upstream and opens an issue when they drift.

## Conventions

- **Behavior over IOCs**, and both KQL and SPL where possible.
- **Confidence = `min(all element confidences)`** — a rule can never be more
  confident than the telemetry under it; the validator enforces this.
- The **validation gate must pass** before any rule is finalized.
- Out of scope unless asked: API deployment, Sigma/YARA-L, org commentary.
