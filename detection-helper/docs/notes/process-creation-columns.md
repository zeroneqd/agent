---
date: "2026-05-28"
source:
  - "docs/advanced-hunting/advanced-hunting-deviceprocessevents-table.md"
  - "docs/tenant/actiontypes/DeviceProcessEvents.md"
scope: "MDE DeviceProcessEvents — all platforms"
confidence: confirmed
---

# Process Creation — Verified Column Reference

**Q:** What columns are available for process creation hunts in MDE?

**A:** DeviceProcessEvents with ActionType == "ProcessCreated". The following columns
are confirmed in the workspace schema and observed in tenant data:

**Process identity:** `FileName`, `FolderPath`, `SHA1`, `SHA256`, `MD5`, `FileSize`,
`ProcessId`, `ProcessCommandLine`, `ProcessIntegrityLevel`, `ProcessTokenElevation`,
`ProcessCreationTime`, `ProcessUniqueId`

**Account context:** `AccountDomain`, `AccountName`, `AccountSid`, `AccountUpn`, `AccountObjectId`, `LogonId`

**Initiating process:** `InitiatingProcessFileName`, `InitiatingProcessFolderPath`,
`InitiatingProcessCommandLine`, `InitiatingProcessSHA1`, `InitiatingProcessId`,
`InitiatingProcessCreationTime`, `InitiatingProcessIntegrityLevel`,
`InitiatingProcessTokenElevation`, `InitiatingProcessUniqueId`

**Ancestry (parent):** `InitiatingProcessParentId`, `InitiatingProcessParentFileName`,
`InitiatingProcessParentCreationTime`

**Version info:** `ProcessVersionInfoOriginalFileName`, `ProcessVersionInfoCompanyName`,
`ProcessVersionInfoProductName`, `ProcessVersionInfoProductVersion`

**Common trap:** `ProcessName` does NOT exist — use `FileName` for the created process
and `InitiatingProcessFileName` for the parent.

**Verification query:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ActionType == "ProcessCreated"
| summarize count(), dcount(DeviceId) by OSPlatform
| order by count_ desc
```
