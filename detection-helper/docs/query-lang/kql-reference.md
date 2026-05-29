# KQL Reference — Advanced Hunting Query Language

> **Purpose.** Comprehensive syntax reference for Kusto Query Language (KQL) as used
> in Microsoft Defender XDR Advanced Hunting and Microsoft Sentinel. Keep this file
> local — KQL syntax evolves slowly and web-fetch for syntax is wasteful.

> **Scope:** Operators, functions, joins, aggregations, time handling, and
> Advanced-Hunting-specific patterns. For table schemas and column names, see
> `docs/advanced-hunting/*.md`. For which table to use, see
> `docs/index/telemetry-index.json`.

-----

## Query structure

```kql
TableName                          // data source
| where Timestamp > ago(7d)        // filtering (must come early)
| where ActionType == "ProcessCreated"
| extend NormalizedPath = tolower(FolderPath)  // calculated columns
| summarize count() by FileName, DeviceName    // aggregation
| order by count_ desc
| take 100                           // limit
```

**Pipe discipline:** Each operator on its own line after `|`. Lowercase operator
names. Queries read top-to-bottom, left-to-right — each pipe feeds the next.

-----

## Essential operators

### Tabular sources

| Operator | Purpose | Example |
|---|---|---|
| `table` | Read from table | `DeviceProcessEvents` |
| `union` | Combine tables | `union DeviceProcessEvents, DeviceFileEvents` |
| `search` | Search across columns | `search "mimikatz"` |
| `find` | Find rows matching predicate | `find in (DeviceProcessEvents) where FileName == "cmd.exe"` |

**Scope `union` carefully.** `union *` scans every table — expensive and slow.
Always specify tables explicitly: `union DeviceProcessEvents, DeviceFileEvents`.

### Filtering

| Operator | Purpose | Example |
|---|---|---|
| `where` | Row filter | `where ActionType == "ProcessCreated"` |
| `where` (compound) | AND conditions | `where ActionType == "ProcessCreated" and FileName == "powershell.exe"` |
| `where` (OR) | OR with `or` | `where ActionType == "FileCreated" or ActionType == "FileModified"` |
| `where` (IN) | Multi-value match | `where ActionType in ("FileCreated", "FileModified", "FileDeleted")` |
| `where` (exists) | Not null / not empty | `where isnotempty(RemoteIP)` |

**String matching hierarchy (performance):**

```kql
// Fastest — exact match (uses index if available)
| where ActionType == "ProcessCreated"

// Very fast — tokenized word match
| where FileName has "evil"           // whole word/token match
| where FileName has_any ("mimikatz", "rubeus", "sharpkatz")
| where FileName has_all ("invoke", "reflective")
| where FileName has_cs "ExactCase"   // case-sensitive

// Medium — prefix/suffix/contains (may scan)
| where FileName startswith "powershell"
| where FileName endswith ".dll"
| where FolderPath contains "\\temp\\"

// Slowest — regex (avoid on large datasets)
| where ProcessCommandLine matches regex @"(?i)-enc.*[A-Za-z0-9+/]{100,}"
```

**Rule:** Prefer `has` over `contains` on high-cardinality columns
(`ProcessCommandLine`, `FolderPath`). `has` performs tokenized matching and
is significantly faster.

### Projection and extension

| Operator | Purpose | Example |
|---|---|---|
| `project` | Select columns | `project Timestamp, DeviceName, FileName, ActionType` |
| `project-away` | Drop columns | `project-away InitiatingProcessVersionInfo*` |
| `project-rename` | Rename columns | `project-rename Host=DeviceName` |
| `extend` | Add computed column | `extend Day = startofday(Timestamp)` |

**Best practice:** `project` early — after initial filters, before joins.
Reduces data movement and improves readability.

### Aggregation

| Operator | Purpose | Example |
|---|---|---|
| `summarize` | Aggregate | `summarize count(), dcount(DeviceId), make_set(FileName) by ActionType` |
| `count` | Row count | `summarize count()` |
| `dcount` | Distinct count | `summarize dcount(DeviceId)` |
| `make_set` | Unique values (set) | `make_set(FileName)` — returns dynamic array |
| `make_list` | All values (with dupes) | `make_list(FileName)` |
| `arg_max` | Row with max value | `arg_max(Timestamp, *) by DeviceId` — latest row per device |
| `arg_min` | Row with min value | `arg_min(Timestamp, *) by DeviceId` — earliest row per device |
| `take_any` | Any single row | `take_any(ProcessCommandLine) by FileName` |

**Common aggregation patterns:**

```kql
// Latest state per device
DeviceInfo
| summarize arg_max(Timestamp, *) by DeviceId

// Event count per device over time
DeviceProcessEvents
| where Timestamp > ago(7d)
| summarize EventCount=count() by DeviceName, Day=startofday(Timestamp)

// Unique ActionTypes observed per table
DeviceEvents
| where Timestamp > ago(1d)
| summarize Types=make_set(ActionType), Total=count() by DeviceName
```

### Sorting and limiting

| Operator | Purpose | Example |
|---|---|---|
| `order by` | Sort | `order by Timestamp desc` |
| `take` / `limit` | Limit rows | `take 100` |
| `top` | Top N by column | `top 10 by count_ desc` |

### Joins

```kql
// Inner join — only matching rows from both sides
DeviceProcessEvents
| where Timestamp > ago(1d)
| join kind=inner (
    DeviceFileEvents
    | where Timestamp > ago(1d)
    | where ActionType == "FileCreated"
) on DeviceId, InitiatingProcessId

// Left outer — all from left, matching from right
| join kind=leftouter (DeviceInfo) on DeviceId

// Left anti — rows in left that DON'T match right (good for gap detection)
| join kind=leftanti (AlertInfo) on DeviceId

// Inner unique — one-to-one, fails if duplicates exist
| join kind=innerunique (Table2) on KeyColumn
```

**Join keys in Advanced Hunting:**
- Device-scoped: `DeviceId`
- Process correlation: `DeviceId` + `InitiatingProcessId` + `InitiatingProcessCreationTime`
- Unique event: `DeviceName` + `Timestamp` + `ReportId`
- Alert: `AlertId`
- Identity: `AccountObjectId`, `AccountSid`

**Join performance rules:**
1. Filter BOTH sides before joining — never join unfiltered tables
2. Join on high-cardinality columns (`DeviceId`, not `AccountName`)
3. Use `hint.strategy=broadcast` when one side is very small (< 10K rows)
4. `project` only needed columns before joining
5. Avoid `join` when `lookup` or ` Mv-expand` can do the job

### Time handling

| Function | Purpose | Example |
|---|---|---|
| `ago(d)` | Relative time | `Timestamp > ago(7d)` |
| `between` | Time range | `Timestamp between (ago(7d)..ago(1d))` |
| `startofday(t)` | Truncate to day | `extend Day = startofday(Timestamp)` |
| `startofhour(t)` | Truncate to hour | `extend Hour = startofhour(Timestamp)` |
| `startofweek(t)` | Truncate to week | `extend Week = startofweek(Timestamp)` |
| `bin(t, interval)` | Bucket by interval | `summarize count() by bin(Timestamp, 1h)` |
| `now()` | Current time | `extend Age = now() - Timestamp` |
| `datetime_add/part` | Date arithmetic | `datetime_add('day', -7, now())` |

**Time literal format:** `datetime(2026-05-28)` or `datetime(2026-05-28T10:30:00Z)`

### String functions

| Function | Purpose | Example |
|---|---|---|
| `tolower()` / `toupper()` | Case conversion | `tolower(FileName)` |
| `trim()` / `trim_start()` / `trim_end()` | Whitespace removal | `trim(ProcessCommandLine)` |
| `replace_regex()` | Regex replace | `replace_regex(@"\\", @"/", FolderPath)` |
| `extract()` | Extract with regex | `extract(@"([0-9]{1,3}\.){3}[0-9]{1,3}", 0, RemoteIP)` |
| `parse` / `parse-where` | Pattern parse | `parse EventData with * 'ScriptBlockId">{' ScriptBlockId '}<' *` |
| `split()` | Split string | `split(FolderPath, "\\")` |
| `strcat()` | Concatenate | `strcat("Domain: ", AccountDomain)` |
| `strlen()` | Length | `strlen(ProcessCommandLine)` |

### IP functions

| Function | Purpose | Example |
|---|---|---|
| `ipv4_is_private()` | Private range check | `where ipv4_is_private(RemoteIP)` |
| `ipv4_is_in_range()` | CIDR check | `where ipv4_is_in_range(RemoteIP, "10.0.0.0/8")` |
| `parse_ipv4()` / `parse_ipv6()` | IP to int | `parse_ipv4(RemoteIP)` |
| `format_ipv4()` | Int to IP | `format_ipv4(ip_int)` |

### JSON / dynamic

| Function | Purpose | Example |
|---|---|---|
| `todynamic()` / `parse_json()` | Parse JSON string | `extend Fields = parse_json(AdditionalFields)` |
| `tostring()` | Cast to string | `tostring(Fields.action)` |
| `tobool()` / `toint()` / `tolong()` | Cast | `toint(Fields.pid)` |
| `bag_keys()` | Dynamic object keys | `bag_keys(AdditionalFields)` |
| `mv-expand` | Expand array/dynamic | `mv-expand Fields` |

### Materialization (performance)

```kql
// Use materialize() when a filtered dataset is used multiple times
let FilteredEvents = materialize (
    DeviceProcessEvents
    | where Timestamp > ago(1h)
    | where FileName in ("powershell.exe", "cmd.exe", "wscript.exe")
);
FilteredEvents
| where ActionType == "ProcessCreated"
| summarize PowerShellCount=count() by DeviceName
;
FilteredEvents
| where ActionType == "ProcessCreated"
| summarize CmdCount=count() by DeviceName
```

-----

## Advanced Hunting-specific patterns

### Process ancestry walk

```kql
// Walk back one parent (built-in InitiatingProcess* columns)
DeviceProcessEvents
| where FileName == "powershell.exe"
| project Timestamp, DeviceName,
    Child=FileName, ChildCmd=ProcessCommandLine,
    Parent=InitiatingProcessFileName, ParentCmd=InitiatingProcessCommandLine,
    Grandparent=InitiatingProcessParentFileName

// Deeper ancestry requires self-join
let Processes = materialize (
    DeviceProcessEvents
    | where Timestamp > ago(1h)
    | project Timestamp, DeviceId, ProcessId, ProcessCreationTime,
              FileName, ProcessCommandLine,
              InitiatingProcessId, InitiatingProcessCreationTime
);
Processes
| where FileName == "powershell.exe"
| join kind=inner (Processes) on $left.InitiatingProcessId == $right.ProcessId,
    $left.DeviceId == $right.DeviceId,
    $left.InitiatingProcessCreationTime == $right.ProcessCreationTime
| project Timestamp, DeviceName=DeviceId,
    Child=FileName, Parent=FileName1, GrandparentCmd=ProcessCommandLine1
```

### Correlation with AlertInfo

```kql
// Find raw events for a specific alert
let TargetAlert = "da637942345600000000_00000000";
AlertEvidence
| where AlertId == TargetAlert
| project DeviceId, SHA1, FileName, ProcessCommandLine
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
) on DeviceId, SHA1
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
```

### Baseline deviation (anomaly)

```kql
// What's unusual today vs last 7 days?
let Today = DeviceProcessEvents
| where Timestamp > ago(1d)
| summarize TodayCount=count() by FileName;
let History = DeviceProcessEvents
| where Timestamp between (ago(8d)..ago(1d))
| summarize AvgDailyCount=count()/7.0 by FileName;
Today
| join kind=inner (History) on FileName
| extend Ratio = TodayCount / AvgDailyCount
| where Ratio > 10
| order by Ratio desc
```

### Throttling / deduplication

```kql
// Bin by time + key, then take first occurrence per bin
DeviceEvents
| where ActionType == "TamperingAttempt"
| summarize arg_min(Timestamp, *) by DeviceId,
    Hour=startofhour(Timestamp)
// One alert per device per hour instead of every event
```

### URL / domain extraction

```kql
// Extract domain from URL
| extend Domain = extract(@"https?://([^/]+)", 1, RemoteUrl)
// Or using parse_url()
| extend Parsed = parse_url(RemoteUrl)
| extend Domain = Parsed.Host
```

### Hash-based correlation

```kql
// Find a file across multiple tables by SHA1
let TargetSHA1 = "aabbccdd...";
union DeviceProcessEvents, DeviceFileEvents, DeviceImageLoadEvents
| where SHA1 == TargetSHA1
| project Timestamp, Table=source_table, DeviceName, FileName, FolderPath, ActionType
| order by Timestamp desc
```

-----

## Performance anti-patterns

| Anti-pattern | Better approach | Why |
|---|---|---|
| `project *` | `project Timestamp, DeviceId, FileName` | Less data movement, faster |
| `where FolderPath contains "temp"` | `where FolderPath has "temp"` | `has` is tokenized, faster |
| `where ProcessCommandLine matches regex @"..."` on full table | Filter with `has` first, then regex | Reduces regex scan set |
| `union *` | `union DeviceProcessEvents, DeviceFileEvents` | `union *` scans all 50+ tables |
| Unfiltered join | Filter both sides first | Dramatically reduces join cardinality |
| `join` on low-cardinality column | Join on `DeviceId` or `SHA1` | High cardinality = faster index lookup |
| `take 100000` without `order by` | `order by Timestamp desc | take 100` | Non-deterministic sampling |
| Nested `extend` chains | `project` early, `extend` only needed columns | Cleaner, sometimes faster |
| Using `contains_cs` when `has_cs` works | `has_cs` for word matching | `has_cs` uses token index |

-----

*Last updated: 2026-05-28. KQL syntax is stable — verify against
[Microsoft KQL documentation](https://learn.microsoft.com/en-us/kusto/query/)
only when adding new operators.*
