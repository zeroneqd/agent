---
primitive: P3
table: DeviceFileEvents
action_types: [FileCreated]
confidence: L4
tenant_observed: true
schema_validated: "2026-05-28"
schema_source: "docs/advanced-hunting/advanced-hunting-devicefileevents-table.md"
---

# P3: Payload File Drop

**Core detection block:**
```kql
DeviceFileEvents
| where Timestamp > ago({{lookback}})
| where ActionType == "FileCreated"
| where InitiatingProcessFileName in ({{parent_processes}})
| where FolderPath has_any ({{suspicious_paths}})
| where FileName has_any ({{executable_extensions}})
| project Timestamp, DeviceName, FileName, FolderPath,
    SHA1, SHA256, Parent=InitiatingProcessFileName,
    ParentCmd=InitiatingProcessCommandLine, AccountName
```

**Required columns:**
- `FileName` [L3], `FolderPath` [L3], `SHA1` [L3], `SHA256` [L3]
- `InitiatingProcessFileName` [L3], `InitiatingProcessCommandLine` [L3]

**Parameters:**
- `parent_processes` — exploited apps (e.g., Office, browsers, Java)
- `suspicious_paths` — user-writable: `C:\Users\`, `\AppData\`, `\Temp\`
- `executable_extensions` — `.exe`, `.dll`, `.ps1`, `.vbs`, `.js`, `.hta`, `.bat`
- `lookback` — default `24h`

**Variants:**

### Unsigned executable from Office
```kql
| where InitiatingProcessFileName in ("winword.exe", "excel.exe", "powerpnt.exe")
| where FileName endswith ".exe"
// Correlate with DeviceFileCertificateInfo for signer check
```

### Double-extension files
```kql
| where FileName matches regex @"\.(pdf|doc|docx|xls|xlsx)\.(exe|js|vbs|hta)$"
```

**FP guidance:** Software installers, browser downloads, legitimate macro-enabled
documents. Baseline by parent process + path.

**Performance:** Fast — single table, indexed columns.
