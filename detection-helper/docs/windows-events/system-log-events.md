# Windows System Event Log Reference

> **Purpose.** Curated reference for the Windows `System` event log — the channel
> that records service, driver, and event-log-service lifecycle. Unlike the
> `Security` channel, most `System` events have **no detection value** (every
> service start, driver load, and time-sync writes here). This file lists only
> the codes that matter for detection engineering, each mapped to its attacker
> behavior and Defender (MDE) equivalent. Do **not** treat the System channel as
> something to ingest wholesale.

## Before reading

- **Channel name:** `System` (Windows Event Log → System).
- **No audit policy required.** Unlike Security events, System events are emitted
  by the providers themselves (Service Control Manager, EventLog, Kernel-Power),
  so they're present by default — but also noisy.
- **Sentinel ingestion:** `Event` table (legacy Log Analytics agent) or
  `WindowsEvent` table (AMA). Filter by `Source`/`Provider` + `EventID`.
- **Splunk ingestion:** `source=WinEventLog:System` /
  `sourcetype=XmlWinEventLog:System`.
- **MDE relationship:** MDE surfaces some of these as `DeviceEvents`
  `ActionType`s (e.g. `ServiceInstalled`), but **service start/stop and
  start-type changes have no distinct MDE ActionType** — the System channel is
  the authoritative source for those. See the gaps per event below.
- **Behavior, not codes.** These IDs are confirmation/secondary signal. Prefer
  the process that *caused* the change (`sc.exe`, `net.exe stop`, `Set-Service`,
  direct `ChangeServiceConfig` API) from `DeviceProcessEvents` as the primary
  detection, and correlate the System event as enrichment.

-----

## Service Control Manager (provider: `Service Control Manager`)

### Event ID 7045 — A new service was installed

**Captures:** installation of a new Windows service (the classic persistence /
lateral-movement primitive behind PsExec, Cobalt Strike, many RATs).

**Key fields:** `ServiceName`, `ImagePath`, `ServiceType`, `StartType`,
`AccountName`.

**Detection relevance:** **P10 (Scheduled Task / Service)** persistence. High
value. Watch for `ImagePath` pointing at `cmd.exe`/`powershell.exe`/temp paths,
unsigned binaries, or `StartType=auto` from a non-installer parent.

**MDE equivalent:** `DeviceEvents` `ActionType == "ServiceInstalled"`; Security
`4697` (requires *Audit Security System Extension*).

### Event ID 7034 — A service terminated unexpectedly

**Captures:** a service crashed (with crash count). Attackers crash AV/EDR or
logging services to blind defenses; also a side effect of process injection into
a service host.

**Detection relevance:** **P6 (Security Tool Disablement)** when the service is a
security product (Sense/MDE, WinDefend, Sysmon, wuauserv). Correlate with a
preceding `OpenProcess`/`TerminateProcess` against the service PID.

**MDE equivalent:** none direct — System channel is authoritative. Pair with
`DeviceProcessEvents` for the initiating actor.

### Event ID 7036 — The service entered the running/stopped state

**Captures:** every service state transition (start/stop). This is the event
behind "stopping a service from the Services UI / `net stop` / `sc stop`".

**Key fields:** `param1` (service display name), `param2` (`running`/`stopped`).

**Detection relevance:** **P6** when a security/logging service is *stopped*
(e.g. `Windows Defender Antivirus Service`, `Microsoft Defender Core Service`,
`Sysmon`, `Windows Event Log`). Very high volume overall — **filter to a
watchlist of protective services**; do not alert on all 7036.

**MDE equivalent:** **no distinct ActionType for service stop/start** — this is a
known MDE visibility gap. Detect the *actor* via `DeviceProcessEvents`
(`net stop`, `sc.exe stop`, `Stop-Service`, `services.msc`) and confirm with 7036.

### Event ID 7040 — The start type of a service was changed

**Captures:** a service's start type changed (e.g. `auto` → `disabled`).
Disabling a security service's auto-start is a common defense-evasion step.

**Detection relevance:** **P6**. Alert on protective services changed to
`disabled`/`demand`. Correlate with `sc config ... start= disabled` in process
telemetry and registry `Start` value writes under
`HKLM\SYSTEM\CurrentControlSet\Services\<svc>` (`DeviceRegistryEvents`).

**MDE equivalent:** registry write to the service `Start` value
(`DeviceRegistryEvents`); no dedicated ActionType.

### Event IDs 7022 / 7023 / 7024 / 7026 / 7031 — Service start/hang/exit errors

**Captures:** service failed to start, hung, exited with an error, or a
boot/system-start driver failed to load. Lower individual value, but a cluster of
these around a security service is a tampering indicator.

**Detection relevance:** **P6** as corroboration only. Treat as enrichment, not a
standalone alert.

-----

## EventLog service (provider: `EventLog` / `Microsoft-Windows-Eventlog`)

### Event ID 104 — The System (or other) event log was cleared

**Captures:** an event log file was cleared. The System-channel counterpart to
Security `1102`. A high-fidelity anti-forensics / defense-evasion signal.

**Key fields:** `SubjectUserName`, `Channel` (which log was cleared).

**Detection relevance:** **P6 / defense evasion**. **Alert on every occurrence**
outside known maintenance — log clearing is rarely legitimate on endpoints.

**MDE equivalent:** Security `1102` (Security log cleared) is the partner event;
no clean MDE ActionType — use the channel events directly.

### Event ID 6005 — The Event Log service was started

**Captures:** event-log service start ≈ system boot. Baseline/anchor event.

**Detection relevance:** low on its own; useful as a **boot marker** to bound a
"what happened right after reboot" hunt, and to detect gaps in logging coverage.

### Event ID 6006 — The Event Log service was stopped

**Captures:** event-log service stop ≈ clean shutdown.

**Detection relevance:** **P6** when 6006 appears *without* a corresponding
shutdown (1074) — a sign logging was stopped while the host stayed up.

### Event ID 6008 — The previous system shutdown was unexpected

**Captures:** the prior shutdown was dirty (crash, power loss, forced reset).

**Detection relevance:** corroboration for destructive activity (wiper, forced
reboot to evade in-memory detection). Pair with `41`.

-----

## Shutdown / power (providers: `User32`, `Microsoft-Windows-Kernel-Power`)

### Event ID 1074 — System shutdown/restart was initiated

**Captures:** a process or user initiated a shutdown/restart, **with the
initiating process and reason**.

**Key fields:** process name, user, reason code, `shutdown`/`restart`.

**Detection relevance:** ransomware and wipers force reboots; unexpected
`shutdown.exe`/`InitiateSystemShutdown` from an odd parent is suspicious.

### Event ID 41 — Kernel-Power: the system rebooted without a clean shutdown

**Captures:** dirty reboot (no preceding 1074/6006). The Kernel-Power partner to
`6008`.

**Detection relevance:** corroboration for destructive or evasive activity.

-----

## Detection guidance

- **Anchor on behavior.** For service tampering, the primary signal is the
  *command/API* (`DeviceProcessEvents`: `net stop`, `sc stop|config|delete`,
  `Stop-Service`, `services.msc`) plus the registry `Start`-value write. The
  System events (7034/7036/7040) are **confirmation**, not the trigger.
- **Watchlist, don't firehose.** 7036 and 7040 are extremely high volume. Scope
  detections to a curated list of protective/logging services.
- **Confidence.** System events are present by default, so schema confidence is
  solid (L3). But because they lack initiator attribution, a rule built *only* on
  a System event is weaker than one that correlates the causing process — reflect
  that in the rule's confidence (see `docs/agent-ref/shared-confidence.md`).

## Cross-references

- `windows-events/security-audit-events.md` — Security channel (4697 service
  install, 1102 log cleared, logon/priv events).
- `windows-events/application-providers.md` — Defender AV, WMI-Activity, MSI.
- `windows-events/defender-to-eventid-mapping.md` — MDE ActionType ↔ event ID.
- `docs/index/telemetry-index.json` — the `Service Control`, `Event Log
  Tampering`, and `Service Installation` actions reference these IDs.
