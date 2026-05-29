# SPL Reference — Splunk Search Processing Language

> **Purpose.** Comprehensive syntax reference for SPL as used in Splunk Enterprise
> and Splunk Cloud for Windows security event hunting. Keep this file local —
> core SPL syntax is stable and web-fetch for syntax is wasteful.

> **Scope:** Search commands, eval functions, time handling, stats, joins, macros,
> and Windows-event-specific field extractions. For which Event ID maps to which
> Defender ActionType, see `docs/windows-events/defender-to-eventid-mapping.md`.

> **Sentinel vs Splunk field names:** Sentinel `SecurityEvent` uses `EventID` and
> `NewProcessName`. Splunk uses `EventCode` and `New_Process_Name`. See the
> `windows-events/README.md` field name comparison table.

-----

## Query structure

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4688
| where New_Process_Name="*\\powershell.exe"
| stats count by ComputerName, New_Process_Name
| sort - count
| head 100
```

**Pipeline discipline:** `|` separates commands. Commands read left-to-right.
SPL is less strict than KQL about formatting but readability still matters.

-----

## Essential commands

### Data retrieval

| Command | Purpose | Example |
|---|---|---|
| `index=` | Specify index | `index=wineventlog` |
| `source=` | Event source | `source="WinEventLog:Security"` |
| `sourcetype=` | Data type | `sourcetype=xmlwineventlog` |
| `host=` | Source machine | `host=DC01` |
| `earliest=` / `latest=` | Time bounds | `earliest=-24h@h latest=now` |
| `eventtype=` / `tag=` | Predefined filters | `eventtype=windows_process_creation` |

**Windows log source patterns:**

```spl
// Windows Security log
index=wineventlog source="WinEventLog:Security"

// Windows System log
index=wineventlog source="WinEventLog:System"

// Sysmon
index=wineventlog source="WinEventLog:Microsoft-Windows-Sysmon/Operational"

// PowerShell
index=wineventlog source="WinEventLog:Microsoft-Windows-PowerShell/Operational"

// PowerShell Core 7+
index=wineventlog source="WinEventLog:PowerShellCore/Operational"

// Windows Defender
index=wineventlog source="WinEventLog:Microsoft-Windows-Windows Defender/Operational"

// Task Scheduler
index=wineventlog source="WinEventLog:Microsoft-Windows-TaskScheduler/Operational"
```

### Filtering

| Command / Syntax | Purpose | Example |
|---|---|---|
| `EventCode=` | Match event ID | `EventCode=4688` |
| `EventCode IN (...)` | Multiple event IDs | `EventCode IN (4688, 4689, 4663)` |
| `field=value` | Exact match | `Image="*\\lsass.exe"` |
| `field!=value` | Not equal | `EventCode!=4624` |
| `field>value` | Comparison | `ProcessId>1000` |
| `field IN (list)` | Value in list | `LogonType IN (2, 10)` |
| `where` | Expression filter | `where like(CommandLine, "% -enc %")` |
| `search` | General search | `search "mimikatz"` |
| `regex` | Regex filter | `regex CommandLine="(?i)-enc\s+[A-Za-z0-9+/]{100,}"` |
| `NOT field=value` | Exclude | `NOT AccountName="SYSTEM"` |

**String matching:**

```spl
// Wildcard (Splunk's default string comparison)
Image="*\\powershell.exe"        // ends with
ProcessName="*evil*"              // contains
ParentImage="C:\Windows\*"        // starts with

// Case-insensitive with wildcards
| where match(Image, "(?i)powershell")

// IN operator for multiple values
EventCode IN (4624, 4625, 4648)
Image IN ("*\\powershell.exe", "*\\pwsh.exe", "*\\cmd.exe")
```

**Time range specifications:**

```spl
// Relative time
earliest=-24h latest=now          // last 24 hours
earliest=-7d@d latest=-1d@d      // last complete 7 days
earliest=-1h@h latest=@h         // last full hour
earliest=@d latest=now           // since midnight
earliest=-15m latest=now         // last 15 minutes

// Snap to time unit
@d = start of day    @h = start of hour    @w = start of week
@mon = start of month    @y = start of year
+1d = add 1 day      -7d = subtract 7 days
```

### Field manipulation

| Command | Purpose | Example |
|---|---|---|
| `fields` | Keep fields | `fields _time, ComputerName, EventCode, Image` |
| `fields -` | Remove fields | `fields - _raw, _time` |
| `rename` | Rename field | `rename New_Process_Name as ProcessName` |
| `eval` | Create/compute field | `eval Day=strftime(_time, "%Y-%m-%d")` |
| `rex` | Regex extraction | `rex field=CommandLine "(?<EncodedPayload>[A-Za-z0-9+/]{100,}=*)"` |
| `extract` | KV extraction | `extract kvps=true` |
| `spath` | JSON/XML path | `spath input=EventData path=Event.EventData.Data{}` |
| `fillnull` | Fill nulls | `fillnull value="N/A" UserName` |
| `eval coalesce()` | First non-null | `eval Account=coalesce(TargetUserName, SubjectUserName)` |

**Common `eval` functions:**

```spl
// String
| eval LowerName=lower(Image)
| eval UpperName=upper(Image)
| eval BaseName=replace(Image, "(.*\\\\)", "")
| eval CleanPath=trim(FolderPath)
| eval Concat=strcat("Process: ", Image, " on ", ComputerName)
| eval Len=len(CommandLine)
| eval IsLong=if(len(CommandLine) > 500, "suspicious", "normal")

// Time
| eval Hour=strftime(_time, "%H")
| eval DayOfWeek=strftime(_time, "%A")
| eval Epoch=strptime(TimeString, "%Y-%m-%d %H:%M:%S")
| eval RelativeTime=relative_time(_time, "-1d@d")

// IP
| eval IsPrivate=if(cidrmatch("10.0.0.0/8", IpAddress) OR cidrmatch("172.16.0.0/12", IpAddress) OR cidrmatch("192.168.0.0/16", IpAddress), "private", "public")

// Conditional
| eval Risk=case(
    EventCode=4688 AND match(CommandLine, "(?i)-enc"), "high",
    EventCode=4624 AND LogonType=10, "medium",
    1=1, "low"
)
| eval Category=if(EventCode IN (4624, 4625), "auth", "other")

// Hash manipulation
| eval MD5Lower=lower(MD5)
| eval SHA1Prefix=substr(SHA1, 1, 8)
```

### Aggregation

| Command | Purpose | Example |
|---|---|---|
| `stats count` | Row count | `stats count` |
| `stats dc()` | Distinct count | `stats dc(ComputerName)` |
| `stats values()` | Unique values | `stats values(Image)` |
| `stats list()` | All values | `stats list(CommandLine)` |
| `stats earliest()` / `latest()` | Time bounds | `stats earliest(_time), latest(_time)` |
| `stats count by field` | Grouped count | `stats count by EventCode, ComputerName` |
| `eventstats` | Stats without collapsing rows | `eventstats count by ComputerName` |
| `streamstats` | Running stats | `streamstats count by ComputerName` |

**Common aggregation patterns:**

```spl
// Event count per host over time
index=wineventlog EventCode=4688
| bin _time span=1h
| stats count as EventCount by ComputerName, _time

// Baseline deviation
index=wineventlog EventCode=4688 Image="*\\powershell.exe"
| bin _time span=1d
| stats count as DailyCount by ComputerName, _time
| eventstats avg(DailyCount) as AvgCount by ComputerName
| eval Ratio=DailyCount/AvgCount
| where Ratio > 5

// First/last occurrence
index=wineventlog EventCode=4697
| stats earliest(_time) as FirstSeen, latest(_time) as LastSeen,
    count as Count by ServiceName, ImagePath
| eval FirstSeen=strftime(FirstSeen, "%Y-%m-%d %H:%M:%S")

// Cardinality check
index=wineventlog EventCode=4624
| stats dc(AccountName) as UniqueAccounts, count as Total by ComputerName
| eval Ratio=Total/UniqueAccounts
```

### Sorting and limiting

| Command | Purpose | Example |
|---|---|---|
| `sort` | Sort ascending | `sort count` |
| `sort -` | Sort descending | `sort - count` |
| `head` / `limit` | First N rows | `head 100` |
| `tail` | Last N rows | `tail 100` |

### Joins and lookups

```spl
// Join (use sparingly — expensive)
index=wineventlog EventCode=4688 Image="*\\evil.exe"
| join ComputerName [
    search index=wineventlog EventCode=4624
    | stats values(AccountName) as LogonAccounts by ComputerName
]

// Lookup (prefer over join — much faster)
| lookup dnslookup clientip as IpAddress OUTPUT clienthost as Hostname

// Input lookup (external CSV)
| inputlookup ioc_sha1.csv
| lookup wineventlog SHA1 as ioc_sha1 OUTPUT ComputerName, _time

// Output to CSV for later use
| outputlookup suspicious_processes.csv
```

**Join performance rules:**
1. Filter the primary search as much as possible before joining
2. Use `join max=0` or `join max=1` to limit match count
3. Prefer `stats` + `selfjoin` patterns over `join` when possible
4. Consider `transaction` for temporal correlation instead of join

### Transaction (temporal correlation)

```spl
// Correlate events into sessions
index=wineventlog (EventCode=4624 OR EventCode=4634)
| transaction AccountName startswith=eval(EventCode=4624) endswith=eval(EventCode=4634)
| eval Duration=duration/60
| where Duration > 0
| table AccountName, Duration, eventcount, _time
```

**Transaction gotchas:**
- Default `maxspan=10m` — increase for longer sessions: `maxspan=8h`
- Default `maxevents=1000` — may truncate long sessions
- Expensive on large datasets — prefer `stats` aggregation when possible

### Subsearches

```spl
// Subsearch returns results that filter main search
index=wineventlog EventCode=4688 [
    search index=wineventlog EventCode=4624 LogonType=10
    | return 100 ComputerName
]

// Return command outputs a field=value list
| return 50 $ComputerName   // returns ComputerName="host1" OR ComputerName="host2" ...
```

**Subsearch limits:**
- Default max results: 10,000
- Default timeout: 60 seconds
- Use `return` to limit result count passed to outer search
- Expensive — prefer `join` or `lookup` for large sets

-----

## Windows event field extraction

### XML EventData parsing (required for detailed fields)

Modern Windows events use XML format. Key fields need explicit extraction:

```spl
// Parse Windows Security event XML
index=wineventlog source="WinEventLog:Security"
| xmlkv
| eval EventData=xmlkv
// OR using rex for specific fields
| rex field=_raw "<Data Name=\"CommandLine\">(?<CommandLine>[^<]+)"
```

**Common Security event fields to extract:**

| Field | EventCode | Extraction |
|---|---|---|
| `CommandLine` | 4688 | `<Data Name="CommandLine">(?<CommandLine>[^<]+)` |
| `NewProcessName` | 4688 | `<Data Name="NewProcessName">(?<NewProcessName>[^<]+)` |
| `ParentProcessName` | 4688 | `<Data Name="ParentProcessName">(?<ParentProcessName>[^<]+)` |
| `TargetUserName` | 4624, 4625 | `<Data Name="TargetUserName">(?<TargetUserName>[^<]+)` |
| `LogonType` | 4624, 4625 | `<Data Name="LogonType">(?<LogonType>\d+)` |
| `IpAddress` | 4624, 4625 | `<Data Name="IpAddress">(?<IpAddress>[^<]+)` |
| `ServiceName` | 4697 | `<Data Name="ServiceName">(?<ServiceName>[^<]+)` |
| `ImagePath` | 4697 | `<Data Name="ImagePath">(?<ImagePath>[^<]+)` |
| `ObjectName` | 4663 | `<Data Name="ObjectName">(?<ObjectName>[^<]+)` |
| `AccessMask` | 4663 | `<Data Name="AccessMask">(?<AccessMask>[0-9A-Fa-f]+)` |

### Sysmon XML field extraction

```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| xmlkv
| eval Image=mvindex('EventData.Image', 0)
| eval CommandLine=mvindex('EventData.CommandLine', 0)
| eval ParentImage=mvindex('EventData.ParentImage', 0)
| eval ParentCommandLine=mvindex('EventData.ParentCommandLine', 0)
| eval TargetImage=mvindex('EventData.TargetImage', 0)
| eval GrantedAccess=mvindex('EventData.GrantedAccess', 0)
| eval SourceImage=mvindex('EventData.SourceImage', 0)
```

**Alternative using `spath` ( cleaner for XML):**
```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| spath output=Image path=EventData.Data{@Name='Image'}
| spath output=CommandLine path=EventData.Data{@Name='CommandLine'}
| spath output=ParentImage path=EventData.Data{@Name='ParentImage'}
```

-----

## Common hunt patterns

### Process LOLBin detection

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4688
| rex field=_raw "<Data Name=\"NewProcessName\">(?<NewProcessName>[^<]+)"
| rex field=_raw "<Data Name=\"CommandLine\">(?<CommandLine>[^<]+)"
| eval ProcessName=replace(NewProcessName, ".*\\\\", "")
| where ProcessName IN ("certutil.exe", "bitsadmin.exe", "mshta.exe",
    "regsvr32.exe", "rundll32.exe", "wscript.exe", "cscript.exe")
| stats count, values(CommandLine) as CommandLines by ComputerName, ProcessName
| sort - count
```

### RDP lateral movement

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4624 LogonType=10
| rex field=_raw "<Data Name=\"IpAddress\">(?<IpAddress>[^<]+)"
| rex field=_raw "<Data Name=\"TargetUserName\">(?<TargetUserName>[^<]+)"
| where NOT cidrmatch("10.0.0.0/8", IpAddress)
  AND NOT cidrmatch("172.16.0.0/12", IpAddress)
  AND NOT cidrmatch("192.168.0.0/16", IpAddress)
  AND IpAddress!="-"
| bin _time span=1h
| stats count as Attempts by _time, ComputerName, IpAddress, TargetUserName
| where Attempts > 5
```

### Service-based persistence

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4697
| rex field=_raw "<Data Name=\"ServiceName\">(?<ServiceName>[^<]+)"
| rex field=_raw "<Data Name=\"ImagePath\">(?<ImagePath>[^<]+)"
| rex field=_raw "<Data Name=\"ServiceType\">(?<ServiceType>[^<]+)"
| where match(ImagePath, "(?i)(C:\\\\Users\\\\|C:\\\\Temp\\\\|C:\\\\Windows\\\\Temp\\\\)")
  OR ServiceType="0x1"
| eval ImagePath=lower(ImagePath)
| stats earliest(_time) as FirstSeen, count by ComputerName, ServiceName, ImagePath
| eval FirstSeen=strftime(FirstSeen, "%Y-%m-%d %H:%M:%S")
```

### Brute-force detection

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4625
| rex field=_raw "<Data Name=\"TargetUserName\">(?<TargetUserName>[^<]+)"
| rex field=_raw "<Data Name=\"IpAddress\">(?<IpAddress>[^<]+)"
| rex field=_raw "<Data Name=\"Status\">(?<Status>[^<]+)"
| bin _time span=5m
| stats dc(TargetUserName) as UniqueTargets, count as Failures by _time, IpAddress
| where UniqueTargets > 5 OR Failures > 10
```

-----

## Performance anti-patterns

| Anti-pattern | Better approach | Why |
|---|---|---|
| `index=*` | `index=wineventlog` | Scans all indexes — very slow |
| Unfiltered subsearch | Filter subsearch, use `return` | Subsearches have 10K limit |
| `join` on unfiltered data | Filter both sides first | Join is O(n*m) |
| `transaction` on millions of events | Use `stats` with `bin _time` | Transaction holds everything in memory |
| `stats count` then `where count>100` | Filter before stats | Reduces aggregation set |
| Regex on `_raw` without `rex` | Use `xmlkv` or `spath` | Structured parsing is faster |
| `sort` before `head` | `head` early if order doesn't matter | Sort is expensive |
| Multiple `eval` with same calc | Single compound `eval` | Fewer pipeline stages |
| `fields + *` after filtering | `fields` right after initial filter | Less data in pipeline |
| `dedup` instead of `stats latest()` | `stats` is usually faster | `dedup` keeps all fields |

-----

## Sentinel-specific notes

When writing for Microsoft Sentinel (Log Analytics / Kusto backend), you use **KQL**
not SPL. However, if the user specifically asks for Splunk syntax targeting data
from a Windows event source, use the patterns above.

**Key differences when the same analyst works across both platforms:**

| Concept | Sentinel (KQL) | Splunk (SPL) |
|---|---|---|
| Time filter | `Timestamp > ago(7d)` | `earliest=-7d@d latest=now` |
| Column/table | `DeviceProcessEvents` | `index=wineventlog source="WinEventLog:Security"` |
| Event ID | `EventID == 4688` | `EventCode=4688` |
| Process name | `FileName` | `New_Process_Name` or extract from XML |
| Command line | `ProcessCommandLine` | Extract from XML `<Data Name="CommandLine">` |
| Computer | `DeviceName` | `ComputerName` |
| Count | `summarize count()` | `stats count` |
| Distinct count | `dcount(DeviceId)` | `dc(ComputerName)` |
| Sort descending | `order by count_ desc` | `sort - count` |
| Limit | `take 100` | `head 100` |
| Time bucket | `bin(Timestamp, 1h)` | `bin _time span=1h` |
| IP private check | `ipv4_is_private(RemoteIP)` | `cidrmatch("10.0.0.0/8", IpAddress)` |

-----

*Last updated: 2026-05-28. Core SPL syntax is stable — update only when Splunk
introduces new commands or Windows changes XML field names.*
