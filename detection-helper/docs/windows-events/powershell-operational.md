# PowerShell Operational Events Reference

> **Purpose.** Per-event-ID reference for `Microsoft-Windows-PowerShell/Operational`
> (Windows PowerShell 5.x) and `PowerShellCore/Operational` (PowerShell 7+).
> Use to translate PowerShell-based MDE hunts into Sentinel `Event` /
> `WindowsEvent` queries and to understand what’s actually captured at each
> logging tier.

## Before reading

- **PowerShell logging is opt-in.** None of these events fire usefully without
  explicit policy enablement. Always verify the policy state before promising
  signal.
- **Three logging tiers exist** (each independent):
1. **Module Logging** — Event 4103. Pipeline-level execution with parameter
   values for configured modules.
1. **Script Block Logging** — Event 4104. The de-obfuscated script content
   itself. This is the high-value tier.
1. **Transcription** — file-based, not event-log. Captures full session
   console I/O. Out of scope for this file but mention it exists.
- **PowerShell 5.x channel:** `Microsoft-Windows-PowerShell/Operational`
- **PowerShell 7+ channel:** `PowerShellCore/Operational` — same event IDs,
  different channel. PowerShell 7 logs there unless reconfigured.
- **Windows PowerShell channel** (different from above):
  `Windows PowerShell` — older, less useful, contains Event 400/600 from the
  classic engine logs.

-----

## Event ID 4100 — PowerShell engine error

**Captures:** errors raised inside the PowerShell engine.

**Detection use:** narrow. Sometimes useful for spotting AMSI bypass attempts
that crash mid-execution. Generally low-signal.

**MDE equivalent:** none direct.

-----

## Event ID 4103 — Module logging (pipeline execution)

**Captures:** invocation of cmdlets within configured modules, including
parameter names and values, the executing user, and the host application.

**Key fields:**

- `Payload` (Message field) — contains the command, parameters, and context
- `ContextInfo` — host application (`powershell.exe`, `pwsh.exe`, integrated
  scripting environment), user, command name, command type
- `UserId`
- `HostApplication`

**Enablement:**

- Group Policy: *Computer Configuration → Administrative Templates → Windows
  Components → Windows PowerShell → Turn on Module Logging*
- Registry: `HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging`
  → `EnableModuleLogging = 1`, plus `ModuleNames` listing modules to log
- Per-module via `Import-Module -LogPipelineExecutionDetails`

**Detection use:**

- Parameter-level visibility for cmdlets (which arguments were passed to
  `Invoke-WebRequest`, `Set-MpPreference`, `Add-LocalGroupMember`, etc.)
- Useful when 4104 captures the script content but 4103 reveals the runtime
  parameter values after variable expansion

**Gotchas:**

- **Only configured modules log.** A `ModuleNames` list of `*` logs everything
  but causes very high volume. Most deployments enumerate specific modules.
- The event message field is the unstructured Payload — KQL parsing is finicky
  (see parsing notes below).
- Pipeline truncation: long pipelines may be split or trimmed.
- `pwsh.exe` (PowerShell 7) logs to its own channel — don’t forget to onboard it.

**MDE equivalent:** partial — `DeviceEvents` with `ActionType == "PowerShellCommand"`
captures *command* invocation. 4103 adds parameter values that aren’t always in
the ActionType payload.

-----

## Event ID 4104 — Script block logging

**The single most important PowerShell detection event.** Captures the
de-obfuscated script block content as PowerShell sees it just before execution
— meaning Base64-encoded, string-concatenated, and string-format-obfuscated
payloads appear here in their decoded form.

**Key fields:**

- `ScriptBlockText` — the decoded script content
- `ScriptBlockId` — GUID identifying the block (correlate multi-part events)
- `MessageNumber` — position in a multi-part series (1-indexed)
- `MessageTotal` — total parts for this block
- `Path` — file path if the script was on disk
- `Level` — Verbose / Warning / Information (see below)

**Enablement:**

- Group Policy: *Computer Configuration → Administrative Templates → Windows
  Components → Windows PowerShell → Turn on PowerShell Script Block Logging*
- Registry: `HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`
  → `EnableScriptBlockLogging = 1`

**Two enablement levels:**

- `EnableScriptBlockLogging = 1` — log all script blocks at `Verbose` level.
  Volume is significant.
- `EnableScriptBlockInvocationLogging = 1` — also log start/stop (4105/4106)
  per invocation. Extra noise; usually skip.

**Automatic logging without enablement:**
Even without explicit policy, PowerShell **auto-logs script blocks containing
suspicious content** at `Warning` level. This is the “free” tier — it catches
classic obfuscation primitives (`FromBase64String`, `IEX`, `New-Object Net.WebClient`,
`DownloadString`, character array tricks, etc.) without any configuration.

**Detection use:**

- De-obfuscated payload visibility — this is where you actually see what
  malicious one-liners do
- AMSI bypass detection — bypass code typically appears here even when AMSI
  itself was tampered with
- Living-off-the-land detection via cmdlet usage patterns

**Gotchas:**

- **Multi-part events.** Large script blocks are split across multiple 4104
  events with the same `ScriptBlockId` and ascending `MessageNumber`. Hunting
  full content requires reassembly:
  
  ```kql
  Event
  | where Source == "Microsoft-Windows-PowerShell" and EventID == 4104
  | parse EventData with * 'ScriptBlockId">{' ScriptBlockId '}<' *
  | parse EventData with * 'ScriptBlockText">' ScriptBlockText '<' *
  | parse EventData with * 'MessageNumber">' MessageNumber:int '<' *
  | parse EventData with * 'MessageTotal">' MessageTotal:int '<' *
  | summarize FullScript = strcat_array(make_list_with_nulls(ScriptBlockText, MessageNumber), "")
      by ScriptBlockId, Computer
  ```
  
  (the above is illustrative — verify field names against your tenant’s
  parsed schema)
- **PowerShell v2 downgrade attack.** Attackers invoke `powershell.exe -Version 2`
  to fall back to the .NET 2.0–era engine that **does not support script
  block logging**. Detect the downgrade itself via `DeviceProcessEvents` /
  Event 4688 with `CommandLine` containing `-Version 2` or `-v 2`.
- **Constrained Language Mode** affects what runs but not what logs. Logging
  still works under CLM.
- **In-memory script blocks** generated via `ScriptBlock::Create()` from a
  dynamic string DO log — this is what catches most in-memory loaders.
- **Volume.** With full logging at Verbose, expect 10–100x the volume of
  Warning-only auto-logging. Plan storage.

**Verbose vs Warning levels:**

- `Information` / `Verbose` (Level 5) — full logging when explicitly enabled
- `Warning` (Level 3) — automatic suspicious-content logging (the “free” tier)

Hunt on `Level == 3` for high-fidelity suspicious-only signal, on `Level == 5`
for everything.

**MDE equivalent:** `DeviceEvents` (`ActionType == "PowerShellCommand"`) —
includes the script content in the `AdditionalFields` payload but with similar
multi-part splitting on very large blocks. MDE is more convenient for
cross-host correlation; 4104 is sometimes more complete for very long blocks.

-----

## Event IDs 4105 / 4106 — Script block invocation start/stop

**Captures:** the moment a script block begins (`4105`) and ends (`4106`)
execution. Only fires when `EnableScriptBlockInvocationLogging = 1`.

**Detection use:** rare — adds noise (every block start/stop) without much
additional fidelity beyond 4104. Useful for runtime timing analysis or for
correlating multi-block execution sequences.

**Recommendation:** leave disabled unless there’s a specific reason to enable.
4104 alone is sufficient for almost all detection.

-----

## Event ID 53504 — Authentication / runspace

**Captures:** PSRemoting runspace authentication details.

**Detection use:** lateral movement via PowerShell Remoting (`Enter-PSSession`,
`Invoke-Command`). Pair with WinRM logs and Security 4624 with LogonType 3.

-----

## Cross-source hunt patterns

### “Suspicious encoded PowerShell command”

**Sentinel `Event` (4688 captures the command-line):**

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "\\powershell.exe" or NewProcessName endswith "\\pwsh.exe"
| where CommandLine has_any ("-enc ", "-EncodedCommand", "-e ", "-ec ")
```

**Sentinel `Event` (4104 captures the decoded content):**

```kql
Event
| where Source == "Microsoft-Windows-PowerShell" and EventID == 4104
| parse EventData with * 'ScriptBlockText">' ScriptBlockText '<' *
| where ScriptBlockText has_any ("FromBase64String", "IEX", "Invoke-Expression",
                                  "DownloadString", "Net.WebClient")
```

**MDE:**

```kql
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has_any ("FromBase64String", "IEX",
                                   "DownloadString", "Net.WebClient")
```

### “PowerShell version downgrade”

```kql
// MDE
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine matches regex @"(?i)(\s-v|\s-version)\s+2(\s|$)"

// Sentinel Security
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "\\powershell.exe"
| where CommandLine matches regex @"(?i)(\s-v|\s-version)\s+2(\s|$)"
```

### “Suspicious script block auto-logged at Warning”

```kql
// Sentinel
Event
| where Source == "Microsoft-Windows-PowerShell" and EventID == 4104
| where Level == 3  // Warning — the auto-suspicious tier
| parse EventData with * 'ScriptBlockText">' ScriptBlockText '<' *
```

Most useful when full 4104 logging isn’t enabled — the auto-Warning tier still
catches a lot.

-----

## What PowerShell logging won’t catch

- **`-Version 2` downgrade** — no 4104 logging in PS v2. Detect the invocation
  itself in `DeviceProcessEvents` / 4688.
- **`.NET Reflection` invocation via C# / `Add-Type`** — code compiled at
  runtime and executed via .NET reflection may bypass 4104. Some signal in
  4103 for the `Add-Type` cmdlet call, but the resulting compiled code runs
  outside PowerShell logging.
- **AMSI-tampered sessions** — AMSI bypass (patching `amsiInitFailed`, hardware
  breakpoints on `AmsiScanBuffer`) silences AMSI but does NOT stop 4104.
  However, AMSI bypass code that runs before any 4104 logging can race;
  bypass primitives usually still appear in 4104 themselves.
- **Encoded commands invoked from non-PowerShell binaries** (e.g. C# runner
  launching a PowerShell runspace via `System.Management.Automation`) — these
  may log differently or not at all depending on host. Check carefully.

-----

## Configuration verification

To check logging state on a sample host:

```powershell
# Module logging
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue

# Script block logging
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue

# Transcription
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue
```

Empty results = not configured via policy. Default behaviour: 4104 auto-logging
at Warning for suspicious content only.

-----

## Caveats

- **PowerShell 7 is a separate beast.** It logs to `PowerShellCore/Operational`
  by default. Same event IDs but a different channel — onboard both, or
  detections only catch Windows PowerShell 5.x.
- **Constrained Language Mode** restricts what runs, not what logs.
- **Just Enough Administration (JEA)** sessions still log normally.
- **Log volume planning matters.** Full 4104 at Verbose can dominate a small
  Sentinel workspace. Filter / route accordingly.

-----

*Last reviewed: 2026-05-27.*