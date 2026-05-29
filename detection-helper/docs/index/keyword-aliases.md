# Keyword Aliases — Fuzzy Matching for telemetry-index.json

> **Purpose.** Maps common user terms to the canonical keywords in
> `docs/index/telemetry-index.json`. When a user's search term doesn't match
> exactly, look up aliases here before falling back to broad search.

## Process execution aliases

| User says | Maps to | Primitive | Table |
|---|---|---|---|
| "process creation" | `ProcessCreated` | P1 | DeviceProcessEvents |
| "new process" | `ProcessCreated` | P1 | DeviceProcessEvents |
| "process spawn" | `ProcessCreated` | P1 | DeviceProcessEvents |
| "child process" | `ProcessCreated` | P1 | DeviceProcessEvents |
| "process launched" | `ProcessCreated` | P1 | DeviceProcessEvents |
| "process start" | `ProcessCreated` | P1 | DeviceProcessEvents |
| "process exit" | `ProcessTerminated` | — | Not logged (gap) |
| "process termination" | `ProcessTerminated` | — | Sysmon 5 / Security 4689 |
| "process died" | `ProcessTerminated` | — | Sysmon 5 / Security 4689 |

## Injection aliases

| User says | Maps to | Primitive | Table |
|---|---|---|---|
| "process injection" | `WriteProcessMemoryApiCall`, `CreateRemoteThreadApiCall` | P2 | DeviceEvents |
| "memory injection" | `WriteProcessMemoryApiCall` | P2 | DeviceEvents |
| "dll injection" | `ImageLoaded` + parent anomaly | P2 | DeviceImageLoadEvents |
| "shellcode injection" | `WriteProcessMemoryApiCall` | P2 | DeviceEvents |
| "remote thread" | `CreateRemoteThreadApiCall` | P2 | DeviceEvents |
| "process hollowing" | Sequence: OpenProcess → WriteProcessMemory → CreateRemoteThread | P2 | DeviceEvents |
| "reflective load" | `ImageLoaded` (unsigned, no parent file) | P12 | DeviceImageLoadEvents |
| "reflective dll" | `ImageLoaded` (unsigned, no parent file) | P12 | DeviceImageLoadEvents |

## File operation aliases

| User says | Maps to | Primitive | Table |
|---|---|---|---|
| "file created" | `FileCreated` | P3 | DeviceFileEvents |
| "file dropped" | `FileCreated` | P3 | DeviceFileEvents |
| "new file" | `FileCreated` | P3 | DeviceFileEvents |
| "file deleted" | `FileDeleted` | P3 | DeviceFileEvents |
| "file removed" | `FileDeleted` | P3 | DeviceFileEvents |
| "file modified" | `FileModified` | P4 | DeviceFileEvents |
| "file changed" | `FileModified` | P4 | DeviceFileEvents |

## Registry aliases

| User says | Maps to | Primitive | Table |
|---|---|---|---|
| "registry key created" | `RegistryKeyCreated` | P5 | DeviceRegistryEvents |
| "registry value set" | `RegistryValueSet` | P5 | DeviceRegistryEvents |
| "registry modification" | `RegistryValueSet` | P5 | DeviceRegistryEvents |
| "registry value changed" | `RegistryValueSet` | P5 | DeviceRegistryEvents |
| "run key" | `RegistryValueSet` under `\Run` or `\RunOnce` | P5 | DeviceRegistryEvents |
| "registry read" | — | — | NOT LOGGED (gap) |

## Network aliases

| User says | Maps to | Primitive | Table |
|---|---|---|---|
| "network connection" | `ConnectionSuccess` | P7 | DeviceNetworkEvents |
| "outbound connection" | `ConnectionSuccess` | P7 | DeviceNetworkEvents |
| "beacon" | `ConnectionSuccess` (repeated pattern) | P7 | DeviceNetworkEvents |
| "c2 connection" | `ConnectionSuccess` | P7 | DeviceNetworkEvents |
| "dns query" | `DnsConnectionInspected` | P8 | DeviceNetworkEvents |
| "dns lookup" | `DnsConnectionInspected` | P8 | DeviceNetworkEvents |
| "domain resolution" | `DnsConnectionInspected` | P8 | DeviceNetworkEvents |
| "dga" | `DnsConnectionInspected` (pattern-based) | P8 | DeviceNetworkEvents |

## Authentication aliases

| User says | Maps to | Table |
|---|---|---|
| "user logon" | `LogonSuccess` | DeviceLogonEvents |
| "user login" | `LogonSuccess` | DeviceLogonEvents |
| "rdp logon" | `LogonSuccess` where LogonType=10 | DeviceLogonEvents |
| "interactive logon" | `LogonSuccess` where LogonType=2 | DeviceLogonEvents |
| "service logon" | `LogonSuccess` where LogonType=5 | DeviceLogonEvents |
| "network logon" | `LogonSuccess` where LogonType=3 | DeviceLogonEvents |
| "kerberos" | `LogonSuccess` | IdentityLogonEvents |
| "ntlm" | `LogonSuccess` | IdentityLogonEvents |
| "ad authentication" | `LogonSuccess` | IdentityLogonEvents |

## Credential access aliases

| User says | Maps to | Primitive | Table |
|---|---|---|---|
| "lsass" | `OpenProcessApiCall` targeting lsass.exe | P11 | DeviceEvents |
| "credential dump" | `OpenProcessApiCall` + `UntrustedExecutableLoadedByLsass` | P11 | DeviceEvents |
| "mimikatz" | `OpenProcessApiCall` + comsvcs.dll patterns | P11 | DeviceEvents |
| "sekurlsa" | `OpenProcessApiCall` | P11 | DeviceEvents |
| "kerberoasting" | `TicketEncryptionType == 0x17` (RC4) | — | IdentityLogonEvents |

## Persistence aliases

| User says | Maps to | Primitive | Table |
|---|---|---|---|
| "scheduled task" | `ScheduledTaskCreated` | P10 | DeviceEvents |
| "task scheduler" | `ScheduledTaskCreated` | P10 | DeviceEvents |
| "new service" | `ServiceInstalled` | P10 | DeviceEvents |
| "service install" | `ServiceInstalled` | P10 | DeviceEvents |
| "wmi persistence" | `WmiBindEventFilterToConsumer` | P9 | DeviceEvents |
| "wmi event subscription" | `WmiBindEventFilterToConsumer` | P9 | DeviceEvents |

## Defense evasion aliases

| User says | Maps to | Primitive | Table |
|---|---|---|---|
| "asr rule" | `AsrOfficeChildProcessBlocked` etc. | P6 | DeviceEvents |
| "amsi bypass" | Script content anomalies | P6 | DeviceEvents |
| "tampering" | `TamperingAttempt` | P6 | DeviceEvents |
| "defender disabled" | Registry changes under `Windows Defender` | P6 | DeviceRegistryEvents |

## Exploitation indicator aliases

| User says | Maps to | Primitive | Table |
|---|---|---|---|
| "office macro" | `ScriptContent` from Office + P1 spawn | P12 | DeviceEvents |
| "browser exploit" | P1 spawn from browser parent | P12 | DeviceProcessEvents |
| "java deserialization" | P1 spawn from java.exe + P7 outbound LDAP | P12 | DeviceProcessEvents |
| "log4shell" | P1 spawn from java.exe + P7 outbound + P8 DNS | P12 | Multiple |

*Last updated: 2026-05-28. Add aliases as new terms are encountered.*
