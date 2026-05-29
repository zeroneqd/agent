---
technique: T1053.005
technique_name: Scheduled Task/Job: Scheduled Task
tactic: TA0003
data_sources: [DeviceEvents, DeviceProcessEvents]
confidence: high
false_positive_rate: medium
last_validated: 2026-05-28
---

# Scheduled Task Creation/Modification for Persistence

Detects creation or modification of scheduled tasks that are commonly abused
for persistence, especially tasks that execute from unusual paths or use system
tools with suspicious command lines.

## Detection logic

1. `DeviceEvents` captures `ScheduledTaskCreated`, `ScheduledTaskUpdated` ActionTypes
2. Correlate with `DeviceProcessEvents` to see the parent process (e.g., `schtasks.exe`)
3. Flag: tasks executing from user-writable paths, tasks with encoded commands,
   tasks created by non-admin processes targeting system locations

## KQL

```kql
// Core detection: suspicious scheduled task creation
let SuspiciousPaths = dynamic([
    @"C:\Users\", @"C:\Temp\", @"C:\Windows\Temp\",
    @"\\AppData\", @"\\Desktop\", @"\\Downloads\"
]);
let SuspiciousCommands = dynamic(["-enc", "-encodedcommand", "powershell",
    "cmd /c", "mshta", "regsvr32", "rundll32", "bitsadmin"]);
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType in ("ScheduledTaskCreated", "ScheduledTaskUpdated")
| extend TaskDetails = parse_json(AdditionalFields)
| extend TaskName = tostring(TaskDetails.TaskName),
         TaskPath = tostring(TaskDetails.TaskPath),
         TaskExec = tostring(TaskDetails.TaskExec)
| where TaskExec has_any SuspiciousPaths
    or TaskExec has_any SuspiciousCommands
    or TaskName startswith @"\"
| project Timestamp, DeviceName, ActionType, TaskName, TaskExec,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          AccountName, ReportId
| order by Timestamp desc
```

## SPL

```spl
index=wineventlog source="WinEventLog:Security" (EventCode=4698 OR EventCode=4702)
| rex field=_raw "<Data Name=\"TaskName\">(?<TaskName>[^<]+)"
| rex field=_raw "<Data Name=\"TaskContent\">(?<TaskContent>[^<]+)"
| rex field=TaskContent "<Command>(?<TaskExec>[^<]+)"
| rex field=TaskContent "<Arguments>(?<TaskArgs>[^<]+)"
| eval TaskExecLower=lower(TaskExec)
| where match(TaskExecLower, "(?i)(users\\\\|temp\\\\|appdata\\\\|desktop\\\\|downloads\\\\)")
    OR match(TaskArgs, "(?i)(-enc|powershell|cmd /c|mshta|regsvr32|rundll32)")
    OR match(TaskName, "^\\\\")
| stats earliest(_time) as FirstSeen, latest(_time) as LastSeen, count,
    values(TaskArgs) as Arguments by ComputerName, TaskName, TaskExec
| eval FirstSeen=strftime(FirstSeen, "%Y-%m-%d %H:%M:%S"), LastSeen=strftime(LastSeen, "%Y-%m-%d %H:%M:%S")
```

## Variants

### High-fidelity: task creation by non-system process

```kql
// Tasks created by processes other than svchost, taskhost, official installers
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType == "ScheduledTaskCreated"
| where InitiatingProcessFileName !in (
    "svchost.exe", "taskhostw.exe", " OfficeClickToRun.exe",
    "GoogleUpdate.exe", "OneDriveSetup.exe"
)
| extend TaskDetails = parse_json(AdditionalFields)
| project Timestamp, DeviceName, TaskName=tostring(TaskDetails.TaskName),
    Creator=InitiatingProcessFileName, CreatorCmd=InitiatingProcessCommandLine,
    AccountName
```

### Known suspicious task names

```kql
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType == "ScheduledTaskCreated"
| extend TaskDetails = parse_json(AdditionalFields)
| extend TaskName = tolower(tostring(TaskDetails.TaskName))
| where TaskName has_any ("update", "system", "windows", "defender",
    "google", "chrome", "adobe")
    and TaskName !contains @"\microsoft\"
    and TaskName !contains @"\google\"
    and TaskName !contains @"\adobe\"
| project Timestamp, DeviceName, TaskName,
    InitiatingProcessFileName, InitiatingProcessCommandLine
```

## False positive guidance

**Expected noise sources:**
- Software installers (Chrome, Office, Adobe) create tasks routinely
- Windows system tasks (`\Microsoft\Windows\*`) are usually benign
- GPO-deployed tasks appear as creations on every domain join/reimage

**Tuning:**
1. Exclude known-good task paths (`\Microsoft\Windows\`, vendor-specific)
2. Exclude known-good creator processes (software updaters)
3. Focus on user-writable execution paths and encoded commands
4. Baseline task creation rate per device type; alert on deviations

**Baseline query:**
```kql
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| extend TaskDetails = parse_json(AdditionalFields)
| summarize count() by TaskName=tostring(TaskDetails.TaskName),
    Creator=InitiatingProcessFileName
| order by count_ desc
```

## Performance notes

- `parse_json(AdditionalFields)` is moderately expensive — filter by
  `ActionType` first (before extend/parse)
- High-volume environments: add `bin(Timestamp, 1h)` and deduplicate
  before projecting details
- Known-noisy environments: pre-filter by `InitiatingProcessFileName`
  before JSON parsing

## Test validation

1. **Benign:** Install Chrome or Office — should NOT alert (excluded paths)
2. **Benign edge:** Create a task via Task Scheduler GUI pointing to `calc.exe` —
   may alert depending on creator process exclusion
3. **Malicious simulation:**
   ```cmd
   schtasks /create /tn "SystemUpdate" /tr "powershell.exe -enc UwB0AGE.." /sc onlogon
   ```
   Should alert on encoded command AND unusual task name

## References

- `docs/advanced-hunting/advanced-hunting-deviceevents-table.md`
- `docs/windows-events/security-audit-events.md` (Events 4698, 4702)
- `docs/notes/anti-patterns.md` (JSON parsing performance)
