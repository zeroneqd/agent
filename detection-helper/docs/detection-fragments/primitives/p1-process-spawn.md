---
primitive: P1
table: DeviceProcessEvents
action_types: [ProcessCreated]
confidence: L4
tenant_observed: true
schema_validated: "2026-05-28"
schema_source: "docs/advanced-hunting/advanced-hunting-deviceprocessevents-table.md"
---

# P1: Process Spawn from Exploited Parent

**Core detection block:**
```kql
DeviceProcessEvents
| where Timestamp > ago({{lookback}})
| where ActionType == "ProcessCreated"
| where InitiatingProcessFileName in ({{parent_processes}})
| where FileName in ({{child_processes}})
| project Timestamp, DeviceName,
    Child=FileName, ChildCmd=ProcessCommandLine,
    Parent=InitiatingProcessFileName, ParentCmd=InitiatingProcessCommandLine,
    Grandparent=InitiatingProcessParentFileName,
    SHA1, AccountName, DeviceId, ReportId
```

**Required columns:**
- `FileName` [L3] — child process name
- `InitiatingProcessFileName` [L3] — parent process name
- `ProcessCommandLine` [L3] — child command line
- `InitiatingProcessCommandLine` [L3] — parent command line
- `InitiatingProcessParentFileName` [L3] — grandparent process
- `SHA1` [L3] — file hash

**Parameters:**
- `parent_processes` — dynamic array of vulnerable parent executables
- `child_processes` — dynamic array of suspicious child executables
- `lookback` — time range (default: `24h`)

**Default child set (suspicious):**
```kql
dynamic(["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "certutil.exe", "bitsadmin.exe", "net.exe", "net1.exe"])
```

**Variants:**

### High-fidelity: specific parent-child pairs
```kql
// Office app + any shell/LOLBin — very high fidelity
let OfficeApps = dynamic(["winword.exe", "excel.exe", "powerpnt.exe"]);
let ShellBins = dynamic(["cmd.exe", "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "certutil.exe"]);
DeviceProcessEvents
| where Timestamp > ago({{lookback}})
| where InitiatingProcessFileName in (OfficeApps)
| where FileName in (ShellBins)
```

### Broad: any vulnerable app + suspicious child
```kql
let VulnerableApps = dynamic([
    "winword.exe", "excel.exe", "powerpnt.exe",
    "acrord32.exe", "acrobat.exe",
    "chrome.exe", "msedge.exe", "firefox.exe",
    "java.exe", "javaw.exe",
    "wscript.exe", "cscript.exe"
]);
```

### Anomaly: parent integrity lower than expected
```kql
| where InitiatingProcessIntegrityLevel == "Medium"
    and ProcessIntegrityLevel == "High"
// Medium-integrity app spawning high-integrity child = UAC bypass or elevation
```

**FP guidance:**
- Office spawning `cmd.exe` is almost never legitimate
- Browsers spawning `cmd.exe` is sometimes legitimate (dev tools, downloads)
- Java spawning shells is rare but may occur in build/CI contexts

**Performance:** Fast — single table, indexed columns (`ActionType`, `FileName`).
