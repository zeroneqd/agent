# Windows Application Channel — Curated Providers

> **Purpose.** The Windows `Application` event log is overwhelmingly noise for
> detection (every app, installer, and .NET runtime writes here). **Do not ingest
> or model the channel wholesale.** A small number of *providers* that happen to
> write to the Application channel — or to their own Operational channels that are
> commonly collected alongside it — carry real signal. This file curates only
> those. Each entry maps to an attacker behavior and the Defender (MDE) equivalent.

## Before reading

- **Channel:** `Application` and a few provider Operational channels
  (`Microsoft-Windows-Windows Defender/Operational`,
  `Microsoft-Windows-WMI-Activity/Operational`). The Defender and WMI-Activity
  events live in their own Operational channels, not literally in `Application`,
  but are grouped here because they're the high-value "application-layer" sources.
- **Sentinel:** `Event` / `WindowsEvent` filtered by `Provider` + `EventID`;
  Defender AV state also surfaces in `DeviceEvents`.
- **Splunk:** `source=WinEventLog:Application` or the provider-specific channel.
- **Behavior first.** As elsewhere, prefer the causing process/registry change as
  the primary detection and use these as confirmation.

-----

## Microsoft Defender Antivirus (provider: `Microsoft-Windows-Windows Defender`)

> Channel: `Microsoft-Windows-Windows Defender/Operational`. The authoritative
> source for AV tampering and on-box malware verdicts.

### Event IDs 1116 / 1117 — Malware detected / action taken

**Captures:** Defender detected malware (1116) and the remediation it applied
(1117 — quarantine, remove, allow, block).

**Detection relevance:** primary AV verdict. **An 1117 with action `Allowed`/
`No action` is a tampering/exclusion red flag.** Correlate with exclusion writes.

**MDE equivalent:** `AlertInfo`/`AlertEvidence`; `DeviceEvents`
`AntivirusDetection`/`AntivirusReport` action types.

### Event ID 5001 — Real-time protection disabled

**Captures:** RTP turned off. Classic **P6 (Security Tool Disablement)**.

**Detection relevance:** **alert on every occurrence**. Pair with the registry
write to `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` or
`Set-MpPreference -DisableRealtimeMonitoring $true` in process telemetry.

### Event ID 5007 — Defender configuration changed

**Captures:** a Defender setting/policy value changed, **with the value path**.

**Detection relevance:** **P6**. Watch for new scan exclusions (paths, processes,
extensions) — a very common evasion step before dropping a payload.

### Event IDs 5010 / 5012 — Antivirus / antispyware scanning disabled

**Detection relevance:** **P6** corroboration alongside 5001/5007.

-----

## WMI-Activity (provider: `Microsoft-Windows-WMI-Activity`)

> Channel: `Microsoft-Windows-WMI-Activity/Operational`. The persistence triplet
> behind WMI event subscriptions — **P9 (WMI Event Subscription)**.

### Event IDs 5857 / 5858 — Provider loaded / operation failed

**Captures:** 5857 = a WMI provider (e.g. `scrcons.exe` script consumer) loaded;
5858 = a WMI query/operation error (with `ClientMachine`, user, `Operation`).

**Detection relevance:** 5857 for `scrcons.exe`/unusual providers; 5858 useful for
remote-WMI recon noise analysis.

### Event IDs 5859 / 5860 / 5861 — Permanent event subscription registered

**Captures:** registration/activity of permanent WMI consumers. **5861** records
the binding of an `__EventFilter` to a `CommandLineEventConsumer`/
`ActiveScriptEventConsumer` — the canonical WMI persistence signature.

**Detection relevance:** **P9**, high value. Alert on 5861 referencing a
`CommandLineEventConsumer`/`ActiveScriptEventConsumer`.

**MDE equivalent:** `DeviceEvents` `ActionType == "WmiBindEventFilterToConsumer"`;
Sysmon 19/20/21.

-----

## Software installation (provider: `MsiInstaller`, Application channel)

### Event IDs 1033 / 1034 — Application installed / removed (MSI)

**Captures:** MSI package install (1033) and removal (1034), with product name and
version.

**Detection relevance:** **P3 (Payload File Drop)** corroboration — rogue MSI as a
delivery/persistence vector (e.g. `msiexec /i http://...`). Lower fidelity; use
with `DeviceProcessEvents` (`msiexec` with remote URL) as the primary.

### Event IDs 11707 / 11708 / 11724 — Install success / failure / removal complete

**Detection relevance:** enrichment for the above; not standalone.

-----

## Application crashes (providers: `Application Error`, `Windows Error Reporting`)

### Event IDs 1000 / 1001 — Application error / WER report

**Captures:** a process crashed (1000, with faulting module/offset) and the WER
record (1001).

**Detection relevance:** **P12 (Vulnerable App Exploitation Indicator)** — repeated
crashes of an internet-facing or parsing process (browser, Office, Exchange
worker, a service host) can indicate exploitation attempts. Baseline first;
crashes are common.

### Event ID 1002 — Application hang

**Detection relevance:** weak corroboration for exploitation/DoS; enrichment only.

-----

## Detection guidance

- **Curate, never firehose the Application channel.** Only the providers above
  carry signal; everything else is operational noise.
- **AV-tampering chain.** The strongest detections combine a Defender event
  (5001/5007) with the *initiating action* (registry policy write,
  `Set-MpPreference`, exclusion add) from `DeviceRegistryEvents`/
  `DeviceProcessEvents`.
- **Confidence.** Defender and WMI-Activity Operational channels must be collected
  to exist in the SIEM — if a tenant doesn't forward them, treat coverage as
  L1/L2, not L3 (see `docs/agent-ref/shared-confidence.md`).

## Cross-references

- `windows-events/system-log-events.md` — System channel (service/log lifecycle).
- `windows-events/security-audit-events.md` — Security channel.
- `windows-events/defender-to-eventid-mapping.md` — MDE ActionType ↔ event ID.
