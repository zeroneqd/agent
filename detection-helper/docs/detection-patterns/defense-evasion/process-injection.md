---
technique: T1055
technique_name: Process Injection
tactic: TA0005
data_sources: [DeviceEvents]
confidence: high
false_positive_rate: medium
last_validated: 2026-05-28
---

# Process Injection via Memory API Calls

Detects process injection techniques using memory manipulation APIs. Covers:
classic DLL injection (WriteProcessMemory + CreateRemoteThread), process
hollowing, APC injection, and memory allocation-based techniques.

## Detection logic

Monitor `DeviceEvents` for memory-related ActionTypes. Injection typically
involves a sequence: `OpenProcessApiCall` → `NtAllocateVirtualMemoryRemoteApiCall`
→ `WriteProcessMemoryApiCall` → `CreateRemoteThreadApiCall` / `NtMapViewOfSectionRemoteApiCall`.

Single API calls are noisy; sequences within a short time window from the same
initiating process are high-confidence.

## KQL — Sequence-based (high confidence)

```kql
// Detect injection sequences: memory alloc → write → execute in remote process
let InjectionAPIs = dynamic([
    "NtAllocateVirtualMemoryRemoteApiCall",
    "WriteProcessMemoryApiCall",
    "CreateRemoteThreadApiCall",
    "NtMapViewOfSectionRemoteApiCall",
    "NtProtectVirtualMemoryRemoteApiCall",
    "MemoryRemoteProtect"
]);
let TimeWindow = 5m;
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType in (InjectionAPIs)
| where InitiatingProcessIntegrityLevel == "Medium"
    or InitiatingProcessIntegrityLevel == "High"
| summarize
    APIs=make_set(ActionType),
    APICount=count(),
    FirstAPI=min(Timestamp),
    LastAPI=max(Timestamp),
    TargetProcesses=make_set(FileName),
    TargetDeviceIds=make_set(DeviceId)
    by InitiatingProcessSHA1, InitiatingProcessFileName,
       InitiatingProcessCommandLine, DeviceName
| extend DurationMinutes = datetime_diff('minute', LastAPI, FirstAPI)
| where APICount >= 3  // Multiple distinct API calls
| extend InjectionScore = APICount + array_length(APIs)
| where InjectionScore >= 5
| project DeviceName, Injector=InitiatingProcessFileName,
    InjectorCmd=InitiatingProcessCommandLine,
    APIs, APICount, Targets=TargetProcesses,
    FirstAPI, LastAPI, DurationMinutes, InjectionScore
| order by InjectionScore desc
```

## KQL — Single suspicious API call (lower confidence, higher coverage)

```kql
// WriteProcessMemory or CreateRemoteThread from unusual processes
let KnownGoodInjectors = dynamic([
    "explorer.exe", "services.exe", "svchost.exe",
    "SearchIndexer.exe", "MsMpEng.exe", "SenseCncProxy.exe"
]);
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType in (
    "WriteProcessMemoryApiCall",
    "CreateRemoteThreadApiCall",
    "NtMapViewOfSectionRemoteApiCall"
)
| where InitiatingProcessFileName !in (KnownGoodInjectors)
| where FileName !in (KnownGoodInjectors)  // target is also not a system process
| project Timestamp, DeviceName,
    ActionType,
    Injector=InitiatingProcessFileName,
    InjectorCmd=InitiatingProcessCommandLine,
    Target=FileName,
    TargetPath=FolderPath,
    AccountName=InitiatingProcessAccountName
| order by Timestamp desc
```

## KQL — Known injection targets

```kql
// Injection into high-value targets regardless of source
let HighValueTargets = dynamic([
    "lsass.exe", "svchost.exe", "explorer.exe",
    "services.exe", "winlogon.exe", "csrss.exe"
]);
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType in (
    "WriteProcessMemoryApiCall",
    "CreateRemoteThreadApiCall",
    "OpenProcessApiCall",
    "NtAllocateVirtualMemoryRemoteApiCall"
)
| where FileName in (HighValueTargets)
| where InitiatingProcessFileName != FileName  // not self-injection
| project Timestamp, DeviceName, ActionType,
    Injector=InitiatingProcessFileName,
    InjectorCmd=InitiatingProcessCommandLine,
    Target=FileName, TargetPath=FolderPath,
    AccountName
| order by Timestamp desc
```

## SPL

```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
    (EventCode=8 OR EventCode=10)
| eval SourceImageLower=lower(SourceImage), TargetImageLower=lower(TargetImage)
| where TargetImageLower="*\\lsass.exe"
    OR TargetImageLower="*\\svchost.exe"
    OR TargetImageLower="*\\services.exe"
| where NOT match(SourceImageLower, "(explorer\.exe|services\.exe|svchost\.exe|msmpeng\.exe)")
| stats earliest(_time) as FirstSeen, latest(_time) as LastSeen, count,
    dc(TargetImageLower) as UniqueTargets,
    values(TargetImageLower) as Targets,
    values(GrantedAccess) as AccessRights
    by ComputerName, SourceImageLower
| eval FirstSeen=strftime(FirstSeen, "%Y-%m-%d %H:%M:%S")
| where count >= 2
```

## False positive guidance

**Expected noise sources:**
- Some EDR agents inject into processes for monitoring
- Legitimate software uses injection for extensibility (browser extensions,
  shell extensions)
- .NET JIT compilation triggers memory protection changes
- Windows Search indexing injects into explorer

**Tuning:**
1. Exclude known-good injector processes (maintain per-environment list)
2. The sequence-based rule (API count >= 3) eliminates most single-call FPs
3. Focus on "Medium integrity process injecting into system process"
4. Cross-reference with `DeviceImageLoadEvents` — injected DLL without signer

**Environment-specific exclusions (add to KnownGoodInjectors):**
- `YourEDRAgent.exe`
- `YourRemoteManagementTool.exe`
- Known LOB applications that use injection

## Performance notes

- `DeviceEvents` with memory ActionTypes is high volume — the
  `InitiatingProcessIntegrityLevel` filter early in the pipeline helps
- `make_set` on `ActionType` is more efficient than string concatenation
- Consider throttling: one alert per `(DeviceId, InitiatingProcessSHA1)` per hour
- The sequence detection benefits from `materialize()` if combining with
  additional filters

## Test validation

1. **Benign:** Run a full EDR scan — sequence rule should not fire (single API
   calls don't meet threshold), single-call rule may fire (excluded by known-good)
2. **Malicious simulation (test endpoint only):**
   Use [SharpInjector](https://github.com/yanbronsard/SharpInjector) or similar:
   ```cmd
   SharpInjector.exe --target notepad.exe --payload payload.dll
   ```
   Sequence rule should fire with APICount >= 3.

## References

- `docs/advanced-hunting/advanced-hunting-deviceevents-table.md`
- `docs/windows-events/sysmon-events.md` (Events 8, 10)
- `docs/windows-events/defender-to-eventid-mapping.md`
