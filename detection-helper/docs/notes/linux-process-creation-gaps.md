---
date: "2026-05-28"
source:
  - "docs/schema-overview.md"
  - "docs/tenant/actiontypes/DeviceProcessEvents.md"
scope: "Linux process creation — MDE"
confidence: confirmed
---

# Linux Process Creation — Known Gaps

**Q:** What's the coverage of process creation on Linux endpoints in MDE?

**A:** `DeviceProcessEvents` with `ActionType == "ProcessCreated"` — **Partial.**

**Confirmed working:**
- Standard process exec paths captured (fork + exec)
- `FileName`, `FolderPath`, `ProcessCommandLine`, `SHA1` populated
- `InitiatingProcess*` ancestry columns available
- Tenant data shows events across Linux devices

**Known gaps:**
- No Windows-style `ProcessIntegrityLevel` — Linux has no equivalent concept
- Short-lived processes via `execveat` paths may not be captured consistently
- Processes that complete between MDE sensor polls may be missed (no termination event)
- Kernel-mode-initiated processes (driver/kthread-spawned) invisible
- WSL2 guest processes only visible with MDE WSL plugin deployed
- Container processes: only visible if host MDE sensor sees them

**Hunting tip:** For Linux process anomalies, pair with:
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where OSPlatform == "Linux"
| where FileName in ("bash", "sh", "dash", "zsh", "python3", "python", "perl", "ruby")
| where InitiatingProcessFileName !in ("sshd", "cron", "systemd")
| summarize count() by FileName, InitiatingProcessFileName
```

**Validation query:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d) and OSPlatform == "Linux"
| where ActionType == "ProcessCreated"
| summarize count(), dcount(DeviceId), arg_min(Timestamp, *), arg_max(Timestamp, *)
```
