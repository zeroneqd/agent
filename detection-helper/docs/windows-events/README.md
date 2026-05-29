# Windows Events Reference Directory

> **Purpose.** This directory contains authoritative references for the three
primary Windows event channels used in detection engineering alongside Microsoft
Defender XDR. Use these files to translate MDE hunts into Sentinel/Splunk queries,
identify Windows-only signal that MDE doesn't surface, and understand channel-specific
prerequisites before promising signal exists.

## Files

| File | Channel | Coverage | When to use |
|---|---|---|---|
| `sysmon-events.md` | Microsoft-Windows-Sysmon/Operational | All 29 events (IDs 1-29) + error 255 | Sysmon-specific questions, process termination (Event 5), clipboard (24), raw disk (9), Sysmon-as-prevention (27-29) |
| `security-audit-events.md` | Security (Windows Event Log) | 30+ key events across authentication, process, object access, account management, Kerberos, AD, network sharing | Audit policy questions, admin-equivalent logons (4672), explicit credentials (4648), process termination (4689), registry OldValue (4657), service/task creation, Kerberos on DCs |
| `powershell-operational.md` | Microsoft-Windows-PowerShell/Operational + PowerShellCore/Operational | Events 4100/4103/4104/4105/4106/53504 | PowerShell logging questions, script block content, module logging, PowerShell 7 channel awareness |
| `defender-to-eventid-mapping.md` | Cross-reference | Defender ActionType → Security/Sysmon/other Event ID mappings | Translating MDE hunts to Sentinel/Splunk, identifying Defender-only vs channel-equivalent signal |

## Quick routing guide

### "I need to detect X — which source should I use?"

| Detection target | Start with | Why |
|---|---|---|
| Process creation | MDE `DeviceProcessEvents` | Always-on, best process ancestry, no config needed |
| Process termination | Sysmon Event 5 or Security 4689 | MDE has no termination event |
| File create/modify/delete | MDE `DeviceFileEvents` | No SACL requirements unlike Security 4663 |
| Registry value set | MDE `DeviceRegistryEvents` | No SACL requirements; broader coverage than Security 4657 |
| Registry value set (with OldValue) | Security 4657 | **Only source that captures previous value** |
| Network connection | MDE `DeviceNetworkEvents` | Lower volume than Security 5156, better metadata |
| Logon success/failure | MDE `DeviceLogonEvents` | Normalised, cross-platform |
| Admin-equivalent logon | Security 4672 | MDE has no privilege-level granularity |
| Explicit credential use (`runas`) | Security 4648 | No MDE equivalent |
| Service install | MDE `DeviceEvents` | Easier correlation with other MDE tables |
| Scheduled task create/update/delete | MDE `DeviceEvents` | Cross-references with process events naturally |
| Account/group changes | MDE `DeviceEvents` | Normalised across local/domain |
| LSASS access / credential dump | Sysmon Event 10 + MDE `DeviceEvents` | Sysmon provides `CallTrace`; MDE provides normalisation |
| WMI persistence | Sysmon Events 19/20/21 + MDE `DeviceEvents` | Sysmon captures filter+consumer separately; MDE captures the binding |
| Named pipe | Sysmon Events 17/18 + MDE `DeviceEvents` | Both sources viable; MDE easier for correlation |
| DNS query | Sysmon Event 22 + MDE `DeviceNetworkEvents` | Both have DoH/DoT blind spots |
| DLL load | MDE `DeviceImageLoadEvents` | Normalised signer/hash info |
| Driver load | Sysmon Event 6 + MDE `DeviceEvents` | Sysmon provides signing detail; MDE provides normalisation |
| PowerShell execution | MDE `DeviceEvents` + native 4104 | MDE for cross-host correlation; 4104 for de-obfuscated content fidelity |
| Kerberos / NTLM on DCs | MDI `IdentityLogonEvents` or Security 4768/4769/4771/4776 | MDI provides cleaner normalisation; Security channel for raw forensic detail |
| AD changes on DCs | MDI `IdentityDirectoryEvents` or Security 5136/5137/5139/5141 | MDI for clean change tracking; Security 5136 for attribute-level forensic detail |
| Audit policy tampering | Security 4719 | No MDE equivalent |
| Raw disk access | Sysmon Event 9 | No MDE equivalent |
| Clipboard activity | Sysmon Event 24 | No MDE equivalent |
| File timestomping | Sysmon Event 2 | MDE has no timestamp-change ActionType |
| Process hollowing / image change | Sysmon Event 25 | No direct MDE ActionType |

### "MDE doesn't show X — where else should I look?"

1. Check `docs/notes/anti-patterns.md` — is it a column name trap?
2. Check `sysmon-events.md` "Sysmon-only signal" section
3. Check `security-audit-events.md` "Security-Only Signals" section
4. Check `defender-to-eventid-mapping.md` — what's the mapped Event ID and does
   it have a prerequisite you missed?
5. If none of the above cover it, the signal may genuinely not be logged by any
   standard channel

## Cross-reference priority

When translating a hunt across sources, follow this order:

1. **MDE** (`Device*Events` tables) — primary, always-on, best correlation
2. **Sysmon** — fills MDE gaps: termination, clipboard, raw disk, hollowing
3. **Security channel** — fills both gaps: audit policy, admin logons, explicit
   credentials, registry OldValue, Kerberos/AD forensic detail on DCs

Use `defender-to-eventid-mapping.md` for the exact Event ID → ActionType
mappings and prerequisite notes.

## Channel comparison

| Characteristic | Security | Sysmon | MDE |
|---|---|---|---|
| Deployment complexity | GPO/auditpol + SACLs for object access | Install + config file | MDE sensor onboarding |
| Always-on | Only if policies enabled | Only if config non-empty | Yes (once onboarded) |
| Volume | High (object access requires SACL tuning) | Config-dependent (can be very high) | Sensor-throttled, sensor-filtered |
| Process ancestry | Limited (4688 has parent via ProcessId only) | ProcessGuid chain | Rich `InitiatingProcess*` columns |
| Cross-device correlation | Manual | Manual (ProcessGuid) | Built-in `DeviceId` |
| Prerequisite sensitivity | High (SACLs, audit policies) | Medium (config selection) | Low (sensor version matters) |
| Registry OldValue | **Yes (4657)** | No | Partial |
| Process termination | **Yes (4689)** | **Yes (Event 5)** | No |
| Platform | Windows only | Windows only | Windows, macOS, Linux |

## Sentinel field name differences

| Concept | `SecurityEvent` table | `WindowsEvent` table | Raw XML |
|---|---|---|---|
| Event ID | `EventID` | `EventID` | `System.EventID` |
| Computer | `Computer` | `Computer` | `System.Computer` |
| Process name | `NewProcessName` | `EventData.NewProcessName` | `EventData.Data[@Name='NewProcessName']` |
| Command line | `CommandLine` | `EventData.CommandLine` | `EventData.Data[@Name='CommandLine']` |
| Account | `Account` | `EventData.SubjectUserName` | varies |
| Time | `TimeGenerated` | `TimeGenerated` | `System.TimeCreated` |

**Important:** Sentinel `SecurityEvent` and `WindowsEvent` are different tables
with different schemas. `SecurityEvent` is the legacy connector format with
pre-parsed fields. `WindowsEvent` requires XML parsing. Verify which connector
is in use before writing queries.

## Splunk field name differences

| Concept | Splunk field |
|---|---|
| Event ID | `EventCode` |
| Process name | `New_Process_Name` |
| Command line | `Process_Command_Line` |
| Account | `user` or `Account_Name` |
| Computer | `host` or `ComputerName` |
| Time | `_time` |

Splunk CIM (Common Information Model) may normalise some of these — check
whether `Accelerated Data Models` are in use.

-----

*Last updated: 2026-05-28. Keep in sync with `docs/VERSION`.*
