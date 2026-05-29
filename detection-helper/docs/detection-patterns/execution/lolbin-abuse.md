---
technique: T1218
technique_name: System Binary Proxy Execution
tactic: TA0002
data_sources: [DeviceProcessEvents]
confidence: high
false_positive_rate: medium
last_validated: 2026-05-28
---

# LOLBin (Living Off The Land Binary) Abuse

Detects abuse of signed, trusted system binaries to execute malicious code.
These binaries are pre-installed on Windows and frequently allowed by application
control policies.

## Detection logic

Monitor `DeviceProcessEvents` for known LOLBins executing with suspicious
command-line patterns. The command line is the key — the binary itself is
legitimate, but the arguments reveal abuse.

## Covered LOLBins

| Binary | Common Abuse Pattern | MITRE Sub-technique |
|---|---|---|
| `certutil.exe` | Download + decode: `-urlcache -split -f http://...` or `-decode` | T1218.007 |
| `bitsadmin.exe` | Download: `/transfer /download http://...` | T1218.007 |
| `mshta.exe` | Execute HTA/JScript: `mshta javascript:...` or remote .hta | T1218.005 |
| `regsvr32.exe` | Execute SCT/remote: `/i:http://... scrobj.dll` | T1218.010 |
| `rundll32.exe` | Execute DLL/JS: `javascript:` or no-argument DLL | T1218.011 |
| `wscript.exe` / `cscript.exe` | Execute JScript/VBScript | T1059.005 / T1059.007 |
| `powershell.exe` / `pwsh.exe` | Encoded commands, download cradles | T1059.001 |
| `cmd.exe` | Batch execution, command obfuscation | T1059.003 |
| `msiexec.exe` | Remote install: `/i http://...` | T1218.007 |
| `installutil.exe` | Execute via installer: `/logfile= /U evil.dll` | T1218.004 |

## KQL — Multi-LOLBin with command-line patterns

```kql
let LOLBins = dynamic([
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "wscript.exe", "cscript.exe", "msiexec.exe",
    "installutil.exe"
]);
let SuspiciousPatterns = dynamic([
    @"-urlcache", @"-split", @"-f http", @"-decode", @"-encode",
    @"/transfer", @"/download", @"javascript:", @"vbscript:",
    @"/i:http", @"/i:https", @"scrobj.dll",
    @"regsvr32", @"/u", @"/s /i",
    @"mshta http", @"mshta vbscript:",
    @"wscript http", @"cscript http"
]);
let Rundll32NoArgPatterns = dynamic([
    @"rundll32.exe", @".dll"
]);
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in (LOLBins)
| extend LowerCmd = tolower(ProcessCommandLine)
| where LowerCmd has_any SuspiciousPatterns
    or (FileName =~ "rundll32.exe"
        and not (LowerCmd contains ".dll," or LowerCmd contains ".dll "))
    or (FileName =~ "regsvr32.exe"
        and (LowerCmd contains "/i:" or LowerCmd contains "/u"))
    or (FileName =~ "certutil.exe"
        and (LowerCmd contains "-urlcache" or LowerCmd contains "-decode"
             or LowerCmd contains "-encode" or LowerCmd contains "-split"))
| project Timestamp, DeviceName,
    LOLBin=FileName, CommandLine=ProcessCommandLine,
    FolderPath, SHA1,
    Parent=InitiatingProcessFileName, ParentCmd=InitiatingProcessCommandLine,
    AccountName, DeviceId, ReportId
| order by Timestamp desc
```

## KQL — PowerShell-specific (high-signal patterns)

```kql
let EncodedPatterns = dynamic([
    @"-enc ", @"-encodedcommand", @"-e ", @"-ec ",
    @"-encoded ", @"frombase64string", @"iex", @"invoke-expression"
]);
let DownloadPatterns = dynamic([
    @"invoke-webrequest", @"iwr", @"wget", @"net.webclient",
    @"downloadstring", @"downloadfile", @"invoke-restmethod",
    @"http://", @"https://", @"bit.ly/", @"pastebin",
    @"githubusercontent", @"transfer.sh"
]);
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in ("powershell.exe", "pwsh.exe")
| extend LowerCmd = tolower(ProcessCommandLine)
| where LowerCmd has_any EncodedPatterns
    or LowerCmd has_any DownloadPatterns
    or LowerCmd matches regex @"(?i)-[eWcQd][\s]*[A-Za-z0-9+/]{50,}"
    or (LowerCmd has "-version" and LowerCmd has "2")
| project Timestamp, DeviceName,
    FileName, CommandLine=ProcessCommandLine,
    Parent=InitiatingProcessFileName, ParentCmd=InitiatingProcessCommandLine,
    AccountName, SHA1
| order by Timestamp desc
```

## KQL — Parent-child anomaly (LOLBin spawned by unusual parent)

```kql
let LOLBins = dynamic([
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "wscript.exe", "cscript.exe"
]);
let ExpectedParents = dynamic([
    "explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
    "services.exe", "taskhostw.exe", "wscript.exe", "cscript.exe"
]);
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in (LOLBins)
| where InitiatingProcessFileName !in (ExpectedParents)
| project Timestamp, DeviceName,
    LOLBin=FileName, LOLBinCmd=ProcessCommandLine,
    Parent=InitiatingProcessFileName, ParentCmd=InitiatingProcessCommandLine,
    Grandparent=InitiatingProcessParentFileName,
    AccountName, SHA1
| order by Timestamp desc
```

## SPL

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4688
| rex field=_raw "<Data Name=\"NewProcessName\">(?<NewProcessName>[^<]+)"
| rex field=_raw "<Data Name=\"CommandLine\">(?<CommandLine>[^<]+)"
| rex field=_raw "<Data Name=\"ParentProcessName\">(?<ParentProcessName>[^<]+)"
| eval ProcessName=lower(replace(NewProcessName, ".*\\\\", "")),
    LowerCmd=lower(CommandLine)
| where ProcessName IN ("certutil.exe", "bitsadmin.exe", "mshta.exe",
    "regsvr32.exe", "rundll32.exe", "wscript.exe", "cscript.exe",
    "msiexec.exe", "installutil.exe")
| where match(LowerCmd, "(?i)(urlcache|split|-f http|decode|transfer|download|javascript|vbscript|scrobj|/i:http)")
    OR (ProcessName="rundll32.exe" AND NOT match(LowerCmd, "\.dll[,\s]"))
    OR (ProcessName="regsvr32.exe" AND match(LowerCmd, "(?i)(/i|/u)"))
| stats earliest(_time) as FirstSeen, latest(_time) as LastSeen, count,
    values(ParentProcessName) as Parents by ComputerName, ProcessName, CommandLine
| eval FirstSeen=strftime(FirstSeen, "%Y-%m-%d %H:%M:%S")
```

## False positive guidance

**Expected noise sources:**
- `certutil -encode` / `-decode` used legitimately for Base64 operations
- `bitsadmin /transfer` used by some installers
- `mshta` used by some LOB applications for legacy HTML dialogs
- `regsvr32 /u` used during software uninstall
- PowerShell download cradles used by legitimate automation

**Tuning:**
1. Exclude known automation accounts / service principals
2. Exclusion list for known-good scripts (by hash or signed path)
3. Focus on encoded commands, remote URLs, and unusual parents
4. Weight by integrity level + parent anomaly score

**Baseline query:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in ("certutil.exe", "bitsadmin.exe", "mshta.exe",
    "regsvr32.exe", "rundll32.exe", "wscript.exe", "cscript.exe")
| summarize count(), make_set(ProcessCommandLine) by FileName, DeviceName
```

## Performance notes

- `ProcessCommandLine` has_any is reasonably efficient with the right tokenization
- `matches regex` is slow — use `has` or `contains` as pre-filters
- The parent-child anomaly rule can be very noisy without exclusions — tune
  `ExpectedParents` for your environment
- Consider materializing LOLBin events if running multiple correlation rules

## Test validation

1. **Benign:** `certutil -encode input.txt output.b64` — may alert (tune for
   local file paths vs remote URLs)
2. **Malicious simulation (safe):**
   ```cmd
   certutil.exe -urlcache -split -f https://www.example.com/robots.txt C:\temp\test.txt
   ```
3. **Encoded command test (safe):**
   ```powershell
   powershell.exe -enc "RwBlAHQALQBQAHIAbwBjAGUAcwBzAA=="  # Base64 of "Get-Process"
   ```

## References

- [LOLBAS Project](https://lolbas-project.github.io/)
- `docs/advanced-hunting/advanced-hunting-deviceprocessevents-table.md`
- `docs/notes/anti-patterns.md` (ProcessName vs FileName)
