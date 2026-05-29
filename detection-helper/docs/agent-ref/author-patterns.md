# Detection Author — Pattern & Fragment Library

> **Loaded by:** `detection-helper.agent.md` (Path C) when adapting patterns or composing
> multi-primitive rules.

## Pattern sources (check in order)

### 1. Detection Fragments (composable, preferred)

Located in `docs/detection-fragments/`. These are reusable building blocks.

**Primitives** (`primitives/`): Single-behavior detection blocks:
- `p1-process-spawn.md` — process spawn from exploited parent
- `p2-code-injection.md` — code injection via memory APIs
- `p3-file-drop.md` — payload file creation
- `p5-registry-persistence.md` — registry Run key modification
- `p6-security-disable.md` — security tool disablement
- `p7-outbound-connection.md` — outbound C2 connection
- `p8-dns-query.md` — DNS query / DGA
- `p9-wmi-subscription.md` — WMI event subscription
- `p10-task-service.md` — scheduled task / service creation
- `p11-lsass-access.md` — LSASS memory access

**Combinators** (`combinators/`): How to combine primitives:
- `early-chain.md` — detect first primitive in kill chain
- `sequence-and.md` — primitive A THEN B within X minutes
- `fallback-or.md` — detect A, or if blind, detect B

**Templates** (`templates/`): Assembly templates:
- `cve-response.md` — full CVE-to-rules assembly

### 2. Detection Patterns (monolithic, reference only)

Located in `docs/detection-patterns/`. Complete rules for specific techniques:
- `persistence/scheduled-task-abuse.md` (T1053.005)
- `credential-access/lsass-access.md` (T1003.001)
- `defense-evasion/process-injection.md` (T1055)
- `execution/lolbin-abuse.md` (T1218)
- `lateral-movement/rdp-lateral-movement.md` (T1021.001)

Use these when a fragment doesn't cover the needed behavior. Decompose them
into fragments when adapting.

## Composition example

**Requirement:** Detect Java deserialization (Log4Shell-style)
**Primitives:** P1 (process spawn) + P7 (outbound) + P8 (DNS)

```markdown
1. Load `p1-process-spawn.md` — get process spawn block
2. Load `p7-outbound-connection.md` — get outbound block
3. Load `p8-dns-query.md` — get DNS block
4. Load `sequence-and.md` — get sequence combinator
5. Assemble: Java parent + (process spawn OR (outbound AND DNS))
6. Result: complete multi-primitive rule
```

## Fragment schema

Every primitive fragment contains:

```markdown
---
primitive: P1
table: DeviceProcessEvents
action_types: [ProcessCreated]
confidence: L3
schema_validated: "2026-05-28"
---

## Core detection block
```kql
<DeviceProcessEvents
| where ActionType == "ProcessCreated"
...
>```

## Required columns
- FileName [L3]
- InitiatingProcessFileName [L3]
- ProcessCommandLine [L3]

## Parameters
- parent_processes: dynamic array of parent executables
- child_processes: dynamic array of child executables
- lookback: time range (default 24h)

## Variants
- High-fidelity: parent-child pair specific
- Broad: any suspicious child from known-vulnerable parent

## FP guidance
...

## Performance notes
...
```

When composing, replace parameters with CVE-specific values.
