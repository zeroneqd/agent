# Anti-Patterns — Common Column and Query Traps

> **Purpose.** Document frequently-hallucinated column names, incorrect ActionType
> spellings, and common query mistakes that produce false negatives. Read this file
> before constructing any KQL query.

-----

## Column name traps

These columns are frequently invented but do NOT exist in the stated tables.
Verify against `docs/advanced-hunting/<table>-table.md` before use.

| Wrong (Do NOT use) | Correct | Table |
|---|---|---|
| `ProcessName` | `FileName` | DeviceProcessEvents |
| `ProcessName` | `InitiatingProcessFileName` | DeviceProcessEvents (parent) |
| `CommandLine` | `ProcessCommandLine` | DeviceProcessEvents |
| `CommandLine` | `InitiatingProcessCommandLine` | DeviceProcessEvents (parent) |
| `UserName` | `AccountName` | Most device tables |
| `UserName` | `InitiatingProcessAccountName` | Most device tables (initiator) |
| `UserDomain` | `AccountDomain` | Most device tables |
| `ImagePath` | `FolderPath` | DeviceImageLoadEvents, DeviceProcessEvents |
| `ParentProcessName` | `InitiatingProcessParentFileName` | DeviceProcessEvents |
| `ParentProcessId` | `InitiatingProcessParentId` | DeviceProcessEvents |
| `RegistryPath` | `RegistryKey` | DeviceRegistryEvents |
| `ValueName` | `RegistryValueName` | DeviceRegistryEvents |
| `ValueData` | `RegistryValueData` | DeviceRegistryEvents |
| `DestIP` | `RemoteIP` | DeviceNetworkEvents |
| `DestPort` | `RemotePort` | DeviceNetworkEvents |
| `SrcIP` | `LocalIP` | DeviceNetworkEvents |
| `SrcPort` | `LocalPort` | DeviceNetworkEvents |
| `FilePath` | `FolderPath` | DeviceFileEvents |
| `PreviousPath` | `PreviousFolderPath` | DeviceFileEvents |
| `SenderEmail` | `SenderFromAddress` | EmailEvents |
| `AttachmentName` | Query `EmailAttachmentInfo` separately | EmailEvents |

**Rule of thumb:** Defender column names are verbose and prefixed. If a column name
sounds short and generic (e.g., `ProcessName`, `UserName`), it's probably wrong.
Prefer the fully-qualified form (`InitiatingProcessAccountName`, not `AccountName`).

-----

## ActionType case sensitivity traps

ActionType filters are **case-sensitive** in KQL. These are exact strings:

| Incorrect | Correct |
|---|---|
| `processcreated` | `ProcessCreated` |
| `Processcreated` | `ProcessCreated` |
| `Filecreated` | `FileCreated` |
| `RegistryValueSet` | `RegistryValueSet` |
| `ConnectionSuccess` | `ConnectionSuccess` |
| `Serviceinstalled` | `ServiceInstalled` |
| `PowershellCommand` | `PowerShellCommand` |
| `ASRRuleBlocked` | `AsrOfficeChildProcessBlocked` (use exact ASR variant) |

**Always** copy ActionType strings from `docs/tenant/actiontypes/` or
`docs/advanced-hunting/` — never type from memory.

-----

## Platform assumption traps

| Assumption | Reality |
|---|---|
| "DeviceRegistryEvents works on Linux" | **Windows ONLY.** No registry on Linux/macOS. |
| "EmailEvents covers on-prem Exchange" | **Exchange Online ONLY.** Requires MDO. |
| "IdentityLogonEvents works without MDI" | **Requires MDI sensor on DCs.** No DC sensor = no events. |
| "AADSignInEventsBeta is GA" | **Beta table.** Schema may change. |
| "ASR rules work on all platforms" | **Windows ONLY.** No ASR on Linux/macOS. |
| "Sysmon events appear in MDE tables" | **No.** Sysmon and MDE are separate sources. MDE tables contain MDE sensor data. |
| "DeviceEvents has a fixed ActionType set" | **Evolves frequently.** Always verify with `summarize count() by ActionType` over 7d. |
| "All Windows events have an MDE equivalent" | **No.** Many are Defender-only (memory APIs, HTTP inspection, ASR, AMSI). |

-----

## KQL syntax traps

| Bad | Good | Why |
|---|---|---|
| `actiontype == "ProcessCreated"` | `ActionType == "ProcessCreated"` | Column names are case-sensitive |
| `where filename contains "evil"` | `where FileName has "evil"` | Use `has` not `contains` on high-cardinality columns |
| `where CommandLine has "-enc"` | `where ProcessCommandLine has "-enc"` | Wrong column name |
| `project *` | `project Timestamp, DeviceId, FileName, ...` | Wide projections hurt performance and readability |
| `join (DeviceInfo)` without kind | `join kind=inner (DeviceInfo)` | Always specify join kind |
| `ago(1d)` for rare events | `ago(7d)` or `ago(30d)` | Rare events need longer lookback |

-----

## Prerequisite traps

Before answering "yes, it's logged", verify these are enabled:

| Signal | Required Prerequisite |
|---|---|
| Security 4688 (process creation) | "Audit Process Creation" + "Include command line" |
| Security 4663 (file access) | Object Access auditing + SACLs on target files |
| Security 4657 (registry value set) | "Audit Registry" enabled |
| Sysmon any event | Sysmon deployed **with a non-empty config** |
| 4104 (script block logging) | `EnableScriptBlockLogging = 1` |
| ASR rule triggers | ASR rules configured in audit or block mode |
| MDI tables | MDI sensor on DCs |
| Email tables | MDO license |
| MDCA tables | Cloud App connectors configured |

**Default assumption:** If the prerequisite isn't confirmed, answer with
"Logged IF <prerequisite> is enabled — verify before deploying detection."

-----

*Last updated: 2026-05-28. Add new traps as they are discovered.*
