# Threat Intelligence Directory

> **Purpose.** Framework and reference for translating external threat
intelligence (CVEs, threat reports, exploit disclosures) into observable OS
operations and detection plans. Used by `detection-helper.agent.md` (Path A).

## Files

| File | Purpose |
|---|---|
| `operation-taxonomy.md` | Maps 12 exploit primitives (P1-P12) to telemetry tables, ActionTypes, detection approaches, blind spots, and kill-chain sequencing. The core translation document. |
| `cve-decomposer.md` | 5-step decomposition pipeline: Extract → Behavioral Analysis → Telemetry Mapping → Gap Analysis → Detection Plan. Includes vulnerability-type → primitive mapping tables and worked example (Log4Shell). |

## Exploit primitives taxonomy

| ID | Primitive | Primary Table | Kill-Chain Position |
|---|---|---|---|
| P1 | Process Spawn from Exploited Parent | `DeviceProcessEvents` | Early |
| P2 | Code Injection | `DeviceEvents` | Early |
| P3 | Payload File Drop | `DeviceFileEvents` | Early-Mid |
| P4 | File Modification (Config Tampering) | `DeviceFileEvents` | Mid |
| P5 | Registry Persistence | `DeviceRegistryEvents` | Mid |
| P6 | Security Tool Disablement | `DeviceRegistryEvents` / `DeviceEvents` | Mid |
| P7 | Outbound Connection (C2) | `DeviceNetworkEvents` | Early-Mid |
| P8 | DNS Query (DGA/C2) | `DeviceNetworkEvents` / Sysmon 22 | Early |
| P9 | WMI Event Subscription | `DeviceEvents` | Mid-Late |
| P10 | Scheduled Task / Service | `DeviceEvents` | Mid-Late |
| P11 | LSASS Memory Access | `DeviceEvents` | Mid |
| P12 | Vulnerable App Exploitation Indicator | `DeviceProcessEvents` | Early |

## Usage flow

```
CVE / Threat Report
    │
    ▼
operation-taxonomy.md   ← "Which primitives does this threat use?"
    │
    ▼
ceve-decomposer.md      ← "How do I map, check gaps, and prioritize?"
    │
    ▼
detection-patterns/     ← "What detection templates exist?"
    │
    ▼
Path C (authoring)      ← "Write the production rules"
```

*Last updated: 2026-05-28*
