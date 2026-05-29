# Detection Patterns Library

> **Purpose.** Curated, tested detection rule templates mapped to MITRE ATT&CK
> techniques. Each pattern includes: KQL and SPL implementations, detection logic
> explanation, false positive guidance, performance notes, and test validation steps.

> **How to use:** The detection author agent loads patterns from this directory
> as starting points. Patterns are technique-scoped, not tool-scoped — a single
> pattern catches multiple tools that share the same behavioral primitive.

## Pattern categories

| Directory | Coverage |
|---|---|
| `persistence/` | Scheduled tasks, services, registry Run keys, WMI subscriptions, startup folders |
| `privilege-escalation/` | UAC bypass, token manipulation, exploitable services |
| `defense-evasion/` | Process injection, AMSI bypass, tampering, obfuscation, timestomping |
| `credential-access/` | LSASS access, SAM/NTDS extraction, Kerberoasting, credential dumping |
| `discovery/` | Account enumeration, network scanning, domain trust discovery |
| `lateral-movement/` | PSExec, WMIexec, RDP hijacking, remote services, SMB execution |
| `execution/` | LOLBins, scripts, COM hijacking, scheduled task abuse |
| `command-and-control/` | DNS tunneling, unusual protocols, beaconing patterns |
| `exfiltration/` | Large transfers, compressed staging, alternate protocols |

## Pattern file format

Every pattern file follows this structure:

```markdown
---
technique: TXXXX.XXX
technique_name: Technique Name
tactic: TA000X
description: What this detects
data_sources: [table1, table2]
confidence: high | medium | low
false_positive_rate: low | medium | high
last_validated: YYYY-MM-DD
---

## Detection logic
...

## KQL
```kql
...
```

## SPL
```spl
...
```

## False positive guidance
...

## Performance notes
...

## Test validation
...
```

## Design principles

1. **Technique-scoped, not tool-scoped.** Catch the behavior, not the binary.
   `rundll32.exe` with no DLL argument catches many loaders — enumerating every
   known loader tool misses future variants.

2. **Multi-source where possible.** Provide KQL (MDE) + SPL (Splunk) + Sentinel
   variants. The detection author selects based on the user's SIEM.

3. **FP-aware from the start.** Every pattern includes baseline expectations and
   tuning guidance. A detection rule without FP management is a noisy alert.

4. **Performance-conscious.** Note high-cardinality operations, expensive joins,
   and suggest materialization or throttling where needed.

5. **Testable.** Every pattern includes validation steps — how to confirm the
   rule works without waiting for a real attacker.

*Last updated: 2026-05-28*
