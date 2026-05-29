# Telemetry Agent — Platform & Edge Case Caveats

> **Loaded by:** `detection-helper.agent.md` (Path B) when the query involves:
> Linux, macOS, containers, WSL, specific sensor versions, or cross-platform coverage.

## Linux coverage matrix

| Table | Linux Coverage | Key Gaps |
|---|---|---|
| `DeviceProcessEvents` | Partial | No integrity level, execveat may miss short-lived, kernel-initiated invisible |
| `DeviceFileEvents` | Partial | fanotify/inotify may miss some I/O paths, network FS writes unreliable |
| `DeviceNetworkEvents` | Partial | Process attribution sometimes stale, loopback not logged, raw sockets invisible |
| `DeviceEvents` | Partial | `KernelModuleLoad`, `BpfFilterAttached`, `PTraceDetected` only |
| `DeviceRegistryEvents` | N/A | No registry on Linux |
| `DeviceImageLoadEvents` | Partial | dlopen-style loads partial coverage |
| `DeviceLogonEvents` | Limited | SSH/console subset, PAM events inconsistent |

**Default stance for Linux:** "Partial" — detection works but has known blind spots.
Always qualify: "Logged on Linux [L3: schema-confirmed] with these gaps: ..."

## macOS coverage matrix

| Table | macOS Coverage | Notes |
|---|---|---|
| `DeviceProcessEvents` | Partial | Narrower than Linux, many ActionTypes absent |
| `DeviceFileEvents` | Partial | Endpoint Security API coverage, not all paths |
| `DeviceNetworkEvents` | Partial | Process attribution gaps |
| `DeviceRegistryEvents` | N/A | No registry |
| `DeviceEvents` | Limited | Fewer ActionTypes than Windows |

**Default stance for macOS:** "Limited" — fewer primitives logged than Linux.

## Container / WSL2 visibility

- **Container processes:** Only visible if host MDE sensor sees them. Namespace
  isolation may hide activity.
- **WSL2 guest processes:** Only visible with MDE WSL plugin deployed. Without
  plugin, WSL activity is invisible.
- **Kubernetes:** MDE for Containers provides pod-level visibility but not
  container-internal processes without specific integration.

## Sensor version dependencies

Some ActionTypes require minimum MDE sensor version. Flag when relevant:

| ActionType | Minimum Sensor | Notes |
|---|---|---|
| `BpfFilterAttached` | 101.23052+ | Linux only |
| `PTraceDetected` | 101.23052+ | Linux only |
| `TamperingAttempt` | 101.98+ | Windows |
| `ScriptContent` | Varies by platform | PowerShell script block capture |

Check `DeviceInfo` table for sensor version per device:
```kql
DeviceInfo
| summarize arg_max(Timestamp, *) by DeviceId
| project DeviceName, OSPlatform, ClientVersion
```

## Windows version differences

- **Windows 7/8.1:** Limited MDE support, some tables partially populated
- **Windows Server 2012 R2:** Full MDE support but fewer built-in protections
- **Windows Server 2019/2022:** Full support, ASR rules available
- **Windows 11:** Latest sensor features, most complete coverage

## High-volume table warnings

These tables generate massive event volume — queries need aggressive filtering:

| Table | Typical volume | Filtering strategy |
|---|---|---|
| `DeviceNetworkEvents` | Very high | Filter by `RemoteIP`, `RemotePort`, `InitiatingProcessFileName` |
| `DeviceProcessEvents` | High | Filter by `FileName`, `ActionType` before joins |
| `DeviceFileEvents` | High | Filter by `FolderPath`, `FileName` |
| `DeviceEvents` | Moderate-High | Filter by `ActionType` (most important) |
| `DeviceRegistryEvents` | Moderate | Filter by `RegistryKey` prefix |
| `DeviceImageLoadEvents` | Very high | Filter by `FileName`, `InitiatingProcessFileName` |

## Cross-SIEM field name traps

| Concept | MDE (KQL) | Sentinel SecurityEvent | Sentinel WindowsEvent | Splunk |
|---|---|---|---|---|
| Event ID | `EventID` | `EventID` | `EventID` | `EventCode` |
| Process name | `FileName` | `NewProcessName` | `EventData.NewProcessName` | `New_Process_Name` |
| Command line | `ProcessCommandLine` | `CommandLine` | `EventData.CommandLine` | extracted from XML |
| Parent process | `InitiatingProcessFileName` | `ParentProcessName` | `EventData.ParentProcessName` | `ParentProcessName` |
| Computer | `DeviceName` | `Computer` | `Computer` | `host` |
| Account | `AccountName` | `Account` | varies | `user` |
| Time | `Timestamp` | `TimeGenerated` | `TimeGenerated` | `_time` |

## Rare edge cases

- **NTFS ADS (Alternate Data Streams):** Partial MDE visibility — `FileName`
  may not include stream name
- **Hard links:** `DeviceFileEvents` fires once per link creation, not per hard link access
- **Symbolic links:** Followed path may differ from queried path
- **Reparse points:** Cloud files (OneDrive) may show as local access but are remote
- **Volume Shadow Copy:** Direct VSS access may not appear in `DeviceFileEvents`
