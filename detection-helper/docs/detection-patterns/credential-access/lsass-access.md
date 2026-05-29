---
technique: T1003.001
technique_name: OS Credential Dumping: LSASS Memory
tactic: TA0006
data_sources: [DeviceEvents, DeviceProcessEvents]
confidence: high
false_positive_rate: medium
last_validated: 2026-05-28
---

# LSASS Memory Access (Credential Dumping)

Detects attempts to dump credentials from LSASS process memory — the primary
method used by tools like Mimikatz, Procdump, comsvc.dll, and various custom
dumpers.

## Detection logic

1. `OpenProcessApiCall` targeting `lsass.exe` — the API call that opens a handle
2. `CreateRemoteThreadApiCall` / `WriteProcessMemoryApiCall` into LSASS — injection
3. `LocalSecurityAuthoritySubsystemServiceProcessAccessDenied` — blocked attempt
4. `UntrustedExecutableLoadedByLsass` — unsigned module loaded into LSASS
5. Correlation: `comsvcs.dll MiniDump` command line (built-in LOLBin)

## KQL — Core detection

```kql
// LSASS handle open with suspicious access rights
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| extend CallTrace = tostring(parse_json(AdditionalFields).CallTrace)
| where InitiatingProcessFileName !in (
    "svchost.exe", "taskhostw.exe", "services.exe",
    "MsMpEng.exe", "SenseCncProxy.exe"
)
| project Timestamp, DeviceName,
    Dumper=InitiatingProcessFileName, DumperPath=InitiatingProcessFolderPath,
    DumperCmd=InitiatingProcessCommandLine, AccessType=ActionType,
    CallTrace, AccountName=InitiatingProcessAccountName
| order by Timestamp desc
```

## KQL — Correlation variant (multiple signals)

```kql
// Any LSASS-related signal, enriched with process context
let LSASSSignals = materialize (
    DeviceEvents
    | where Timestamp > ago(24h)
    | where ActionType in (
        "OpenProcessApiCall",
        "LocalSecurityAuthoritySubsystemServiceProcessAccessDenied",
        "UntrustedExecutableLoadedByLsass",
        "CreateRemoteThreadApiCall",
        "WriteProcessMemoryApiCall"
    )
    | where FileName =~ "lsass.exe"
    or (ActionType == "CreateRemoteThreadApiCall"
        and InitiatingProcessFileName =~ "lsass.exe")
);
LSASSSignals
| summarize
    SignalTypes=make_set(ActionType),
    SignalCount=count(),
    FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp),
    Dumpers=make_set(InitiatingProcessFileName),
    DumperCmds=make_set(InitiatingProcessCommandLine)
    by DeviceName, DeviceId
| extend SignalCount = array_length(SignalTypes)
| where SignalCount >= 2  // Multiple signal types = higher confidence
| order by SignalCount desc, LastSeen desc
```

## KQL — comsvcs.dll MiniDump (LOLBin)

```kql
// Built-in credential dumping via comsvcs.dll
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has "comsvcs.dll" and ProcessCommandLine has "MiniDump"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    AccountName, DeviceId, ReportId
```

## KQL — Procdump targeting LSASS

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "procdump.exe" or FileName =~ "procdump64.exe"
| where ProcessCommandLine has "lsass"
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
```

## SPL

```spl
index=wineventlog (source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10)
    OR (source="WinEventLog:Security" EventCode=4663)
| eval Image=coalesce(Image, New_Process_Name)
| where match(lower(TargetImage), "lsass\.exe$")
| where NOT match(lower(SourceImage), "(svchost\.exe|taskhostw\.exe|services\.exe|msmpeng\.exe)")
| rex field=GrantedAccess "(?<AccessHex>0x[0-9A-Fa-f]+)"
| where AccessHex IN ("0x1010", "0x1410", "0x143A", "0x1438", "0x1FFFFF")
| stats earliest(_time) as FirstSeen, latest(_time) as LastSeen, count,
    values(GrantedAccess) as AccessRights, values(CallTrace) as Traces
    by ComputerName, SourceImage, TargetImage
| eval FirstSeen=strftime(FirstSeen, "%Y-%m-%d %H:%M:%S")
```

## False positive guidance

**Expected noise sources:**
- Some EDR/AV products legitimately open LSASS for memory scanning
- Windows Credential Manager operations
- Legitimate debugging by admins

**Tuning:**
1. Maintain exclusion list for known security tools
2. Alert on `CallTrace` containing unknown/untrusted DLLs
3. Weight by `InitiatingProcessIntegrityLevel` — medium integrity accessing
   LSASS is more suspicious than system integrity
4. Cross-reference with `DeviceImageLoadEvents` — unsigned dumper loading into LSASS

**Known-good process exclusion (environment-specific):**
```kql
| where InitiatingProcessFileName !in (
    "YourEDRAgent.exe",       // replace with your EDR
    "YourAVScanner.exe"       // replace with your AV
)
```

## Performance notes

- `OpenProcessApiCall` targeting LSASS is moderate volume — filter by
  `InitiatingProcessFileName` exclusions before aggregation
- The correlation variant using `materialize()` is important when joining
  multiple signal types — LSASS events cluster by time
- `parse_json(AdditionalFields)` is only needed for `CallTrace` enrichment —
  consider a two-pass approach: alert first, enrich second

## Test validation

1. **Benign:** Run your EDR scan cycle — should NOT alert (known-good exclusion)
2. **Benign edge:** Open Task Manager and view LSASS details — no alert
3. **Malicious simulation (safe):**
   ```cmd
   :: Requires admin — do NOT run in production without approval
   tasklist /svc /fi "imagename eq lsass.exe"
   ```
   This only lists — no dump. For a real test, use a test endpoint with
   [mimikatz](https://github.com/gentilkiwi/mimikatz) or procdump:
   ```cmd
   procdump.exe -accepteula -ma lsass.exe lsass.dmp
   ```
4. **LOLBin test (safe):**
   ```cmd
   :: This requires admin and will create a dump file
   rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\temp\lsass.dmp full
   ```

## References

- `docs/advanced-hunting/advanced-hunting-deviceevents-table.md`
- `docs/windows-events/sysmon-events.md` (Event 10)
- `docs/windows-events/security-audit-events.md` (Event 4663)
