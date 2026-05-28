# Sysmon Operational Events Reference

> **Purpose.** Per-event-ID reference for `Microsoft-Windows-Sysmon/Operational`.
> Use to translate Defender hunts into Sysmon-equivalent queries, identify
> Sysmon-only signal MDE doesn’t surface, and understand Sysmon’s detection
> ceiling.

## Before reading

- **Sysmon does nothing useful out of the box.** The default install ships with
  an empty configuration. A meaningful deployment uses a curated config file —
  the SwiftOnSecurity baseline and Olaf Hartong’s modular config are the
  community references. **Always ask which config is deployed** before promising
  signal exists.
- **Sysmon overlaps heavily with MDE.** Many shops run one but not both — pick
  the source that matches the environment, don’t assume both.
- **Channel name:** `Microsoft-Windows-Sysmon/Operational`
- **Provider GUID:** `{5770385f-c22a-43e0-bf4c-06f5698ffbd9}`
- **Sentinel ingestion:** via `Event` table (older agent) or `WindowsEvent` /
  `SecurityEvent` depending on collection config. The Sysmon Data Connector
  surfaces events under `Event` with `Source == "Microsoft-Windows-Sysmon"`.
- **Process correlation key:** `ProcessGuid` is unique across reboots and
  better than `ProcessId` for ancestry chains.

-----

## Event ID 1 — Process creation

**Captures:** every process start.

**Key fields:** `Image`, `CommandLine`, `CurrentDirectory`, `User`, `LogonId`,
`IntegrityLevel`, `Hashes` (configurable: MD5, SHA1, SHA256, IMPHASH),
`ParentProcessGuid`, `ParentImage`, `ParentCommandLine`, `OriginalFileName`
(PE metadata — useful for renamed binaries), `ProcessGuid`.

**Detection use:** the workhorse event for process-based detection.
LOLBin abuse, suspicious parent-child relationships, command-line obfuscation,
renamed binaries (via `OriginalFileName` mismatch).

**Gotchas:**

- Hash types depend on config — IMPHASH is invaluable for malware family
  clustering but isn’t on by default in all configs
- `OriginalFileName` only populated when the PE has it
- Very short-lived processes (< sensor poll window) occasionally missed
- High-volume processes (build agents, AV scanners) often excluded by config

**MDE equivalent:** `DeviceProcessEvents` (`ActionType == "ProcessCreated"`).

-----

## Event ID 2 — File creation time changed

**Captures:** attempts to backdate a file’s creation timestamp (`timestomping`).

**Key fields:** `Image` (process that did it), `TargetFilename`,
`CreationUtcTime`, `PreviousCreationUtcTime`.

**Detection use:** anti-forensics signal. Legitimate uses are rare — installers
occasionally do it, but attacker tooling does it routinely to blend in.

**Gotchas:**

- Narrowly scoped — does NOT capture file content modification, only timestamp
  manipulation. Easy to confuse with “file modified”.
- High false-positive rate from some installers and backup software — needs
  baseline tuning.

**MDE equivalent:** no direct ActionType. Partial visibility through
`DeviceFileEvents` correlated with process behaviour.

-----

## Event ID 3 — Network connection

**Captures:** TCP and UDP connections (initiated, not listening).

**Key fields:** `Image`, `User`, `Protocol`, `Initiated` (true = outbound),
`SourceIp`, `SourcePort`, `DestinationIp`, `DestinationPort`,
`DestinationHostname`, `DestinationIsIpv6`.

**Detection use:** C2 beaconing, lateral movement (SMB/WMI/WinRM), unusual
process-to-destination mappings.

**Gotchas:**

- **Volume is enormous** by default — most configs aggressively filter
  (exclude browsers, system processes, RFC1918 destinations) or only include
  specific processes
- `DestinationHostname` populated only if reverse DNS succeeds — often empty
- Connections via DNS-over-HTTPS appear as ordinary HTTPS to the DoH provider
- No payload visibility — just metadata

**MDE equivalent:** `DeviceNetworkEvents` (`ConnectionSuccess`,
`ConnectionAttempt`).

-----

## Event ID 4 — Sysmon service state changed

**Captures:** Sysmon service start/stop/config-change events.

**Key fields:** `State`, `Version`, `SchemaVersion`.

**Detection use:** tamper detection — attackers stopping Sysmon to evade
logging. Also useful for detecting Sysmon config swaps.

**Gotchas:** a sophisticated attacker who stops Sysmon also stops these
events from reaching the SIEM. Pair with EDR/MDE health checks rather than
relying on absence.

**MDE equivalent:** none directly. Closest is `DeviceEvents` tamper-related
ActionTypes for Defender itself.

-----

## Event ID 5 — Process terminated

**Captures:** process exit.

**Key fields:** `ProcessGuid`, `ProcessId`, `Image`, `UtcTime`.

**Detection use:** correlation — pair with Event 1 to compute process lifetime,
detect crashes, build complete process timelines.

**Gotchas:** no exit code. For exit code, fall back to `Security` 4689 (if
“Audit Process Termination” is enabled).

**MDE equivalent:** no direct ActionType for termination (visibility gap).

-----

## Event ID 6 — Driver loaded

**Captures:** kernel driver loads.

**Key fields:** `ImageLoaded`, `Hashes`, `Signed`, `Signature`,
`SignatureStatus`.

**Detection use:** rootkit detection, BYOVD (bring-your-own-vulnerable-driver)
attacks — exactly the kind of thing where `Signed == "true"` doesn’t mean safe
(`Signature` and `SignatureStatus` reveal whether the cert is revoked, expired,
or from an attacker-abused signer).

**Gotchas:**

- Signature validation is at load time — drivers signed with later-revoked
  certs still appear “signed”
- Microsoft has a known Vulnerable Driver Blocklist — cross-reference loaded
  drivers against it

**MDE equivalent:** `DeviceEvents` (`ActionType == "DriverLoad"`).

-----

## Event ID 7 — Image loaded (DLL)

**Captures:** module loads into running processes.

**Key fields:** `Image` (loading process), `ImageLoaded` (the DLL),
`Hashes`, `Signed`, `Signature`, `SignatureStatus`, `OriginalFileName`.

**Detection use:**

- LSASS module loads (credential theft tooling, custom SSPs)
- DLL hijacking / search-order hijacking
- Side-loading via signed-but-vulnerable hosts
- Unsigned DLLs loaded by signed processes

**Gotchas:**

- **Very high volume.** Most configs only enable this selectively (per-process
  inclusion rules) — full Event 7 logging at scale is impractical
- **Reflective loads invisible** — DLLs loaded from memory never trigger this
- Module unloads NOT logged

**MDE equivalent:** `DeviceImageLoadEvents` (`ActionType == "ImageLoaded"`).

-----

## Event ID 8 — CreateRemoteThread

**Captures:** a process creating a thread in *another* process’s address space.

**Key fields:** `SourceImage`, `SourceProcessGuid`, `TargetImage`,
`TargetProcessGuid`, `StartAddress`, `StartModule`, `StartFunction`.

**Detection use:** classic process injection. The `StartAddress` /
`StartModule` fields are the high-value bit — injection into `kernel32!LoadLibrary`
or unbacked memory regions is a strong signal.

**Gotchas:**

- Modern injection techniques bypass this (APC injection, thread hijacking,
  hardware breakpoints, `SetThreadContext` via remote API)
- Legitimate uses exist (debuggers, profilers, some AV products)

**MDE equivalent:** `DeviceEvents` (`ActionType == "CreateRemoteThreadApiCall"`).

-----

## Event ID 9 — RawAccessRead

**Captures:** a process opening a handle to a raw disk volume (`\\.\C:` style).

**Key fields:** `Image`, `Device`.

**Detection use:** disk-level access for credential extraction (NTDS.dit
copy via Volume Shadow Copy), evidence destruction tooling, low-level forensic
tooling.

**Gotchas:** legitimate uses are limited but not zero — backup software,
some AV products, defragmenters. Baseline first.

**MDE equivalent:** no clean direct ActionType. Partial signal via correlated
`DeviceFileEvents` on the resulting copies.

-----

## Event ID 10 — ProcessAccess

**Captures:** one process opening a handle to another with elevated rights.

**Key fields:** `SourceImage`, `SourceProcessGuid`, `TargetImage`,
`TargetProcessGuid`, `GrantedAccess`, `CallTrace`.

**Detection use:** the LSASS-dumping detection — `TargetImage == "lsass.exe"`
with high access rights (`0x1010`, `0x1410`, `0x143A` etc.). `CallTrace`
reveals which DLLs in the source process initiated the access, exposing
tooling like Mimikatz / pypykatz.

**Gotchas:**

- Volume is high — needs filtering by `TargetImage` or `GrantedAccess`
- `CallTrace` parsing is finicky — module names followed by `+offset`,
  needs careful tokenisation
- Many legitimate Windows processes access LSASS at low privilege levels —
  filter on `GrantedAccess` carefully

**MDE equivalent:** `DeviceEvents` (`ActionType == "OpenProcessApiCall"`).

-----

## Event ID 11 — FileCreate

**Captures:** file creation.

**Key fields:** `Image`, `TargetFilename`, `CreationUtcTime`.

**Detection use:** dropped payloads, persistence files (Startup folder,
scheduled task XML, service binaries), suspicious extensions in unusual paths.

**Gotchas:**

- File modification NOT captured — Event 11 is creation only
- No hash in Event 11 (correlate with Event 1 if the file then gets executed)
- High volume on busy systems — usually filtered by path or extension

**MDE equivalent:** `DeviceFileEvents` (`ActionType == "FileCreated"`).

-----

## Event ID 12 — RegistryEvent (Object create and delete)

**Captures:** registry key create and delete (NOT value changes — see Event 13).

**Key fields:** `EventType` (“CreateKey” or “DeleteKey”), `TargetObject`,
`Image`.

**Detection use:** persistence keys (`Run`, `RunOnce`, `Image File Execution Options`, Services), tooling traces.

**MDE equivalent:** `DeviceRegistryEvents` (`RegistryKeyCreated`,
`RegistryKeyDeleted`).

-----

## Event ID 13 — RegistryEvent (Value Set)

**Captures:** registry value writes.

**Key fields:** `EventType` (“SetValue”), `TargetObject`, `Details` (new
value), `Image`.

**Detection use:** the highest-value registry event — captures both the path
and the new value. Persistence detection, configuration tampering, defence
disabling (Defender exclusions, audit policy).

**Gotchas:**

- `Details` truncated for large values — full content may be missing for
  binary or very large strings
- Does NOT capture previous value (unlike Security 4657)
- Very high volume — must be config-filtered

**MDE equivalent:** `DeviceRegistryEvents` (`RegistryValueSet`).

-----

## Event ID 14 — RegistryEvent (Key and Value Rename)

**Captures:** rename operations on keys and values.

**Key fields:** `EventType` (“RenameKey”), `TargetObject`, `NewName`,
`Image`.

**Detection use:** rare but high-fidelity — registry renames are uncommon
in legitimate operation.

**MDE equivalent:** `DeviceRegistryEvents` (`RegistryKeyRenamed`).

-----

## Event ID 15 — FileCreateStreamHash

**Captures:** creation of Alternate Data Streams on NTFS files.

**Key fields:** `Image`, `TargetFilename` (includes `:StreamName`),
`CreationUtcTime`, `Hash`.

**Detection use:** ADS-based payload hiding, mark-of-the-web propagation
(`Zone.Identifier` stream is the legitimate-use baseline).

**Gotchas:** `Zone.Identifier` is the normal one — filter it out or it dominates.

**MDE equivalent:** partial — `DeviceFileEvents` doesn’t distinguish ADS
writes from regular file creation reliably.

-----

## Event ID 16 — Sysmon configuration change

**Captures:** Sysmon config file changes.

**Detection use:** tamper detection — config swap to silence specific events.

**MDE equivalent:** none direct.

-----

## Event ID 17 — PipeEvent (Pipe Created)

**Captures:** named pipe creation.

**Key fields:** `Image`, `PipeName`.

**Detection use:** lateral movement tooling (PsExec, Impacket), C2 frameworks
(Cobalt Strike default pipe names are well-known IOCs), inter-process comms
of malware.

**Gotchas:** high volume from system processes — filter `\\.\pipe\srvsvc`,
`lsass` defaults, etc. before alerting.

**MDE equivalent:** `DeviceEvents` (`ActionType == "NamedPipeEvent"`).

-----

## Event ID 18 — PipeEvent (Pipe Connected)

**Captures:** named pipe client-side connection.

**Key fields:** `Image`, `PipeName`.

**Detection use:** companion to Event 17 — Event 18 reveals which process
connected to a suspicious pipe.

**MDE equivalent:** `DeviceEvents` (`ActionType == "NamedPipeEvent"`).

-----

## Event IDs 19, 20, 21 — WmiEvent (Filter / Consumer / Binding)

**Captures:** WMI permanent event subscription components.

- **19** = `WmiEventFilter activity detected` (filter creation)
- **20** = `WmiEventConsumer activity detected` (consumer creation)
- **21** = `WmiEventConsumerToFilter activity detected` (binding — the persistence)

**Key fields:** `Operation`, `User`, `EventNamespace`, `Name`, `Query`
(filter), `Type` (consumer), plus binding fields linking them.

**Detection use:** WMI persistence is a high-fidelity signal — these events
fire rarely in legitimate operation. Event 21 (the binding) is the
“persistence activated” moment.

**Gotchas:** `__EventFilter` and `CommandLineEventConsumer` are the classic
malicious combinations. Be familiar with `ActiveScriptEventConsumer` too.

**MDE equivalent:** `DeviceEvents`
(`ActionType == "WmiBindEventFilterToConsumer"` and adjacent).

-----

## Event ID 22 — DNSEvent (DNS query)

**Captures:** DNS queries made via Windows DNS resolver.

**Key fields:** `Image`, `QueryName`, `QueryStatus`, `QueryResults`.

**Detection use:** DNS-based C2, DGA detection, DNS tunneling indicators,
beacon-domain hunting.

**Gotchas:**

- **DoH and DoT bypass this** — queries go via HTTPS/TLS directly to the
  resolver, never touching Windows DNS client
- Hardcoded resolvers in malware (direct UDP/53 to a custom server) bypass too
- Volume is enormous — most configs filter aggressively (exclude Microsoft
  telemetry domains, CDN noise)

**MDE equivalent:** `DeviceNetworkEvents` (`ActionType == "DnsConnectionInspected"`)
— but with similar limitations.

-----

## Event ID 23 — FileDelete (archived)

**Captures:** file deletion **with content archived** to the Sysmon archive
directory.

**Key fields:** `Image`, `TargetFilename`, `Hashes`, `IsExecutable`,
`Archived` (true).

**Detection use:** anti-forensics defeated — even if attacker deletes their
tooling, Sysmon retains a copy for analysis.

**Gotchas:**

- Archive directory grows fast — needs disk capacity planning
- Only configured paths/extensions are archived (config-driven)
- Default archive directory: `C:\Sysmon`

**MDE equivalent:** `DeviceFileEvents` (`ActionType == "FileDeleted"`) — but
MDE does NOT archive the file content.

-----

## Event ID 24 — ClipboardChange

**Captures:** clipboard write events.

**Key fields:** `Image`, `Session`, `ClientInfo`, `Hashes`, `Archived`.

**Detection use:** rare but useful for specific scenarios — clipboard
hijacking for cryptocurrency address swapping, RDP-clipboard data exfil.

**Gotchas:** very high volume in interactive sessions if not filtered.
Most configs disable this entirely.

**MDE equivalent:** none direct.

-----

## Event ID 25 — ProcessTampering (image change)

**Captures:** process hollowing / image replacement — when the in-memory
image of a process differs from its on-disk image.

**Key fields:** `Image`, `Type` (“Image is replaced” or “Process Herpaderping”).

**Detection use:** highly specific — Process Hollowing (RunPE), Process
Herpaderping, Process Doppelgänging detection.

**Gotchas:**

- Sysmon 13+ required
- Modern variants (Ghosting, Phantom DLL hollowing) may evade

**MDE equivalent:** no direct ActionType. Detected indirectly through memory
ActionTypes in `DeviceEvents`.

-----

## Event ID 26 — FileDeleteDetected (no archive)

**Captures:** file deletion **without** archiving content.

**Key fields:** same as Event 23 but `Archived` = false.

**Detection use:** when you want delete signal without the archive cost.

**MDE equivalent:** `DeviceFileEvents` (`ActionType == "FileDeleted"`).

-----

## Event ID 27 — FileBlockExecutable

**Captures:** Sysmon blocked the *creation* of an executable file matching
a `FileBlockExecutable` rule.

**Key fields:** `Image` (creating process), `TargetFilename`, `Hashes`.

**Detection use:** Sysmon-as-prevention — block known-bad file drops to
specific paths.

**Gotchas:**

- Sysmon 13.30+ required
- Blocking-mode rules need careful authoring; false positives can break
  legitimate software installations
- Detection AND prevention from one tool — useful but adds operational risk

**MDE equivalent:** ASR rules (`Asr*Blocked` ActionTypes in `DeviceEvents`).

-----

## Event ID 28 — FileBlockShredding

**Captures:** Sysmon blocked an attempt to securely delete (shred) a file.

**Key fields:** similar to Event 27.

**Detection use:** anti-forensics defence — block evidence destruction.

**Gotchas:**

- Sysmon 13.40+ required
- Narrow use case

**MDE equivalent:** none direct.

-----

## Event ID 29 — FileExecutableDetected

**Captures:** the creation of an executable file (PE) — alerting-only,
without blocking.

**Key fields:** `Image` (creator), `TargetFilename`, `Hashes`.

**Detection use:** baseline alerting for executables dropped into unusual
paths (Temp, AppData, user-writable directories).

**Gotchas:**

- Sysmon 14+ required
- Volume manageable if scoped to specific paths

**MDE equivalent:** partial — `DeviceFileEvents` plus extension filtering.

-----

## Event ID 255 — Error

**Captures:** Sysmon internal errors.

**Detection use:** health monitoring. Errors during config load or rule
evaluation indicate the deployment is partially broken.

-----

## Cross-source hunt patterns

### “DLL injection into LSASS”

**Sysmon:**

```
EventID == 10 AND TargetImage endswith "\\lsass.exe"
  AND GrantedAccess in ("0x1010", "0x1410", "0x143A", "0x1438")
```

**MDE:**

```kql
DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where FileName == "lsass.exe"
```

### “Suspicious named pipe creation”

**Sysmon:**

```
(EventID == 17 OR EventID == 18)
  AND PipeName matches "(?i)\\\\(MSSE-|postex_|status_|msagent_)"
```

**MDE:**

```kql
DeviceEvents
| where ActionType == "NamedPipeEvent"
| where AdditionalFields has_any ("MSSE-", "postex_", "status_", "msagent_")
```

### “WMI persistence binding”

**Sysmon:**

```
EventID == 21
```

**MDE:**

```kql
DeviceEvents
| where ActionType == "WmiBindEventFilterToConsumer"
```

-----

## Sysmon-only signal (no MDE equivalent)

These events have no clean Defender ActionType — they require Sysmon to be
deployed:

- Event 2 (timestamp manipulation) — anti-forensics
- Event 4 (Sysmon service state) — tamper detection on Sysmon itself
- Event 9 (RawAccessRead) — raw disk handle opens
- Event 15 (ADS hash) — stream-level visibility
- Event 16 (Sysmon config change) — tamper detection
- Event 24 (clipboard) — clipboard activity
- Event 25 (ProcessTampering) — hollowing/herpaderping detection
- Events 27–29 (file block / detect) — Sysmon-as-prevention

When the question is “can MDE see X?” and X is in this list, the answer is
generally **no — Sysmon required** (or correlate post-hoc behaviour in MDE).

-----

## Configuration baseline notes

- **SwiftOnSecurity** (`sysmon-config`) — community standard, conservative,
  good starting point
- **Olaf Hartong** (`sysmon-modular`) — modular, MITRE-ATT&CK-mapped, more
  comprehensive
- **Florian Roth** — variants tuned for high-fidelity detection
- Whichever you start with, **tune it** for your environment — defaults
  always produce false-positive churn from build agents, AV products, and
  remote management tooling

-----

## Caveats

- **Schema version matters.** Sysmon’s event schema has evolved across
  versions. Older deployments lack newer events (25, 27–29).
- **Config drift is common.** Multiple Sysmon configs in an estate
  (different teams, image versions) produce inconsistent telemetry — hunt
  results may vary by host.
- **Sysmon is opt-in detection.** Unlike MDE (always-on once onboarded),
  Sysmon’s coverage depends entirely on its config. Verify per-host.

-----

*Last reviewed: 2026-05-27.*