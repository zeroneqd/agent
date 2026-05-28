# Notes — curated detection findings

Per-session, user-curated findings from prior agent sessions. Treated as
trusted supplementary context by `.github/agents/defender-telemetry.agent.md`.

## When to add a note

Add a note when an agent session has surfaced one of:

- A non-obvious telemetry **gap** (e.g. an ActionType documented but not
  emitted in tenant, or a sensor blind spot confirmed through testing).
- A reusable **verification pattern** (KQL/SPL that materially helps
  confirm a control's presence).
- A **CVE-specific** hunt finding worth keeping (only when the
  table/ActionType mapping is non-trivial).

Do **not** add a note for things already in `docs/advanced-hunting/`,
`docs/schema-overview.md`, or `docs/tenant/`. Notes are for the marginal
discovery, not duplication of upstream schema docs.

## Format

One file per finding, slug-named:

```
docs/notes/<short-slug>.md
```

Every note must include:

- **Date** — ISO-8601 date the finding was confirmed.
- **Source** — workspace files or authoritative web URLs cited
  (`learn.microsoft.com`, `github.com/MicrosoftDocs`,
  `techcommunity.microsoft.com`).
- **Scope** — platform / sensor version / workload constraints under
  which the finding holds.
- **Body** — the finding itself, with verification query where
  applicable.

## Capture pattern

The agent proposes a note as a code block at the end of its response;
the user accepts explicitly before the file is created. The agent does
not write notes autonomously.

## Storage

Local, version-controlled. Do **not** sync to cloud-hosted memory
stores or GitHub-hosted Copilot Memory.
