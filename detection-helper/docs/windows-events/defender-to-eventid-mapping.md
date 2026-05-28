# Defender Advanced Hunting → Event ID Mapping

> **Purpose.** For each Defender XDR Advanced Hunting table and ActionType, list
> the underlying Windows Security event IDs, Sysmon event IDs, and other channel
> events that produce equivalent signal. Use this to:
> 
> - Translate an MDE hunt into a Sentinel `SecurityEvent` / `WindowsEvent` query
>   or a Splunk `wineventlog` search
> - Identify the raw event a Defender ActionType derives from
> - Spot Sysmon-only signals MDE doesn’t surface (and vice versa)

## How to read this file

- **One-to-many is normal.** A single Defender ActionType often aggregates several
  raw event IDs.
- **Prerequisites matter.** Many Windows Security events require specific audit
  policies (SACLs, Advanced Audit Configuration) to fire. Sysmon events require
  Sysmon to be deployed *and* configured. Missing prereqs = silent gaps.
- **Sysmon overlaps heavily with MDE.** Many shops do not deploy both. If a
  question assumes Sysmon presence, verify before answering.
- **”—” means no clean equivalent.** The signal is Defender-only (sensor-derived,
  not from a standard Windows channel).
- **Channels referenced:**
  - `Security` — Windows Event Log → Security
  - `System` — Windows Event Log → System
  - `Sysmon` — `Microsoft-Windows-Sysmon/Operational`
  - `PS-Op` — `Microsoft-Windows-PowerShell/Operational`
  - `Defender-Op` — `Microsoft-Windows-Windows Defender/Operational`
  - `TaskSched-Op` — `Microsoft-Windows-TaskScheduler/Operational`
  - `WMI-Activity` — `Microsoft-Windows-WMI-Activity/Operational`
  - `Kernel-PnP` — `Microsoft-Windows-Kernel-PnP/Configuration`
  - `SmartScreen` — `Microsoft-Windows-SmartScreen/Debug`

-----

## DeviceProcessEvents

|ActionType      |Security|Sysmon|Notes                                                                                                                                                                                                   |
|----------------|--------|------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|`ProcessCreated`|4688    |1     |4688 requires “Audit Process Creation”; command line requires the separate “Include command line in process creation events” policy. Sysmon 1 captures hashes, parent process, integrity level natively.|

**Process termination** is not a `DeviceProcessEvents` ActionType in current MDE
— if you need termination signal, fall back to `Security 4689` or `Sysmon 5`.
This is a real visibility gap when hunting short-lived processes that complete
between MDE sensor polls.

**Sysmon advantages over 4688:** image hashes, signing info, parent command line,
integrity level, original file name (PE metadata), session GUID.

**MDE advantages over Sysmon 1:** consistent normalisation, process tree
correlation via `InitiatingProcess*` columns, cross-device correlation.

-----

## DeviceFileEvents

|ActionType    |Security             |Sysmon                        |Notes                                                                                                                                              |
|--------------|---------------------|------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
|`FileCreated` |4663                 |11                            |Security 4663 requires a file SACL — usually only enabled on sensitive paths. Sysmon 11 captures file creates broadly per config.                  |
|`FileModified`|4663                 |2 (FileCreateTime change only)|True file content modification has no clean Sysmon event; Sysmon 2 only catches timestamp manipulation. MDE here captures more than either channel.|
|`FileDeleted` |4660 (+ 4663 context)|23 (archived) / 26 (detected) |4660 fires only with an associated 4663; 23 archives the file content, 26 logs the delete without archive.                                         |
|`FileRenamed` |4663                 |11 + 23 (paired)              |No single rename event in either channel — surfaces as delete + create.                                                                            |

**Prerequisites for Security channel:** Object Access auditing enabled AND
explicit SACLs on the file/folder. In practice, most shops don’t run wide file
SACLs because of volume — MDE/Sysmon are the realistic sources.

**Sysmon 2** is narrowly scoped to file *creation time* changes (anti-forensics
signal), not general file modification. Don’t confuse with “file modified”.

-----

## DeviceRegistryEvents

|ActionType            |Security          |Sysmon|Notes                                                                                           |
|----------------------|------------------|------|------------------------------------------------------------------------------------------------|
|`RegistryKeyCreated`  |4656 + 4663       |12    |Sysmon 12 covers both key create and key delete (distinguish by `EventType` field in the event).|
|`RegistryKeyDeleted`  |4656 + 4663 + 4660|12    |—                                                                                               |
|`RegistryKeyRenamed`  |—                 |14    |Sysmon 14 is the only direct rename signal.                                                     |
|`RegistryValueSet`    |4657              |13    |4657 is the cleanest Security channel signal; includes old + new value.                         |
|`RegistryValueDeleted`|4657              |13    |4657 indicates a deletion when new value is empty.                                              |

**Prerequisites for Security channel:** “Audit Registry” enabled AND SACLs on
target keys. Without SACLs, only 4657 (with the right subcategory enabled) gives
broad value-set coverage.

**Registry reads (`RegQueryValueEx` etc.) are not logged by any source** —
MDE, Sysmon, and Security channel all lack this. Detection of reconnaissance
against the registry has to come from process behaviour, not registry events.

-----

## DeviceNetworkEvents

|ActionType                    |Security|Sysmon|Notes                                                                                                                                           |
|------------------------------|--------|------|------------------------------------------------------------------------------------------------------------------------------------------------|
|`ConnectionSuccess` (outbound)|5156    |3     |5156 = Filtering Platform Connection allowed. Requires the “Audit Filtering Platform Connection” subcategory — very high volume, often disabled.|
|`ConnectionFailed`            |5157    |—     |5157 = blocked by WFP. No Sysmon equivalent.                                                                                                    |
|`InboundConnectionAccepted`   |5156    |3     |Direction inferred from process and ports.                                                                                                      |
|`ListeningConnectionCreated`  |5158    |—     |5158 = port binding (listen).                                                                                                                   |
|`DnsConnectionInspected`      |—       |22    |Sysmon 22 = DNS query (resolver-level). MDE here captures DNS via the sensor’s network stack hook.                                              |
|`HttpConnectionInspected`     |—       |—     |Defender-only — derived from network sensor inspection, no clean channel equivalent.                                                            |
|`SslConnectionInspected`      |—       |—     |Defender-only.                                                                                                                                  |

**Sysmon 3 vs. MDE network events:** Sysmon 3 includes process attribution
directly but doesn’t surface inbound metadata as cleanly. MDE adds DNS/HTTP/SSL
inspection layers Sysmon doesn’t provide.

**Loopback traffic** (`127.0.0.0/8`, `::1`) is generally filtered out by
both MDE and Sysmon by default.

-----

## DeviceLogonEvents

|ActionType      |Security|Notes                                                                                                                               |
|----------------|--------|------------------------------------------------------------------------------------------------------------------------------------|
|`LogonSuccess`  |4624    |LogonType in the event distinguishes interactive (2), network (3), batch (4), service (5), unlock (7), remote interactive (10), etc.|
|`LogonFailed`   |4625    |SubStatus codes reveal cause (bad password, expired, locked out, etc.).                                                             |
|`LogonAttempted`|—       |Defender-derived — covers some pre-4625 attempt signal.                                                                             |

**Adjacent useful Security events not in `DeviceLogonEvents` directly:**

|Event ID|Meaning                                                                                              |
|--------|-----------------------------------------------------------------------------------------------------|
|4634    |Logoff                                                                                               |
|4647    |User-initiated logoff                                                                                |
|4648    |Logon using explicit credentials (`runas`, scheduled task, etc.) — high-value lateral movement signal|
|4672    |Special privileges assigned to new logon (admin-equivalent logon)                                    |
|4778    |RDP session reconnected                                                                              |
|4779    |RDP session disconnected                                                                             |

**Kerberos and NTLM events on DCs** surface in `IdentityLogonEvents`
(MDI required), not `DeviceLogonEvents`. See the IdentityLogonEvents section.

-----

## DeviceImageLoadEvents

|ActionType   |Security|Sysmon|Notes                                                                                                                                     |
|-------------|--------|------|------------------------------------------------------------------------------------------------------------------------------------------|
|`ImageLoaded`|—       |7     |No native Windows Security event for general DLL loads — Sysmon 7 is the only standard channel source. MDE adds signer/hash normalisation.|

**Reflective DLL loads** (image never touches disk) are missed by both MDE
`DeviceImageLoadEvents` and Sysmon 7. Hunt those via memory ActionTypes in
`DeviceEvents` (`NtAllocateVirtualMemoryRemoteApiCall`,
`NtProtectVirtualMemoryRemoteApiCall`).

-----

## DeviceEvents (selected high-value ActionTypes)

`DeviceEvents` is the catch-all — only the most commonly mapped ActionTypes are
listed. Many are Defender-derived with no native event channel equivalent.

### Process injection / memory manipulation

|ActionType                            |Sysmon        |Notes                                                               |
|--------------------------------------|--------------|--------------------------------------------------------------------|
|`OpenProcessApiCall`                  |10            |Sysmon 10 = ProcessAccess. The classic LSASS dump detection.        |
|`OpenThreadApiCall`                   |10 (sometimes)|Coverage varies.                                                    |
|`CreateRemoteThreadApiCall`           |8             |Sysmon 8 is the cleanest signal for classic remote-thread injection.|
|`WriteProcessMemoryApiCall`           |—             |No clean Sysmon equivalent.                                         |
|`ReadProcessMemoryApiCall`            |—             |—                                                                   |
|`NtAllocateVirtualMemoryRemoteApiCall`|—             |—                                                                   |
|`NtProtectVirtualMemoryRemoteApiCall` |—             |—                                                                   |
|`MemoryRemoteProtect`                 |—             |—                                                                   |

**This category is where MDE outclasses Sysmon meaningfully** — the memory API
ActionTypes surface injection primitives Sysmon simply doesn’t see.

### Drivers and kernel

|ActionType                 |Security|Sysmon|System                  |Notes                                                                                              |
|---------------------------|--------|------|------------------------|---------------------------------------------------------------------------------------------------|
|`DriverLoad`               |—       |6     |7045 (if service-loaded)|Sysmon 6 with signing info is the cleanest. 7045 only fires for drivers loaded via service install.|
|`KernelModuleLoad` (Linux) |—       |—     |—                       |Linux-only, no Windows equivalent.                                                                 |
|`BpfFilterAttached` (Linux)|—       |—     |—                       |Linux-only.                                                                                        |

### Scheduled tasks

|ActionType            |Security   |TaskSched-Op|Notes                                                                      |
|----------------------|-----------|------------|---------------------------------------------------------------------------|
|`ScheduledTaskCreated`|4698       |106         |4698 includes the task XML in the event data — high-value forensic content.|
|`ScheduledTaskUpdated`|4702       |140         |—                                                                          |
|`ScheduledTaskDeleted`|4699       |141         |—                                                                          |
|(enabled/disabled)    |4700 / 4701|142         |Not surfaced as distinct ActionTypes in `DeviceEvents`.                    |

### Services

|ActionType        |Security|System|Notes                                                                                                                                             |
|------------------|--------|------|--------------------------------------------------------------------------------------------------------------------------------------------------|
|`ServiceInstalled`|4697    |7045  |7045 is the de facto standard — used by everyone for service-based persistence detection. 4697 requires “Audit Security System Extension” enabled.|

### WMI

|ActionType                    |Sysmon|WMI-Activity|Notes                                                                                                  |
|------------------------------|------|------------|-------------------------------------------------------------------------------------------------------|
|`WmiBindEventFilterToConsumer`|21    |5861        |Sysmon 19 (filter create), 20 (consumer create), 21 (binding) form the classic WMI persistence triplet.|

### PowerShell

|ActionType         |Security                                 |PS-Op      |Notes                                                                                                                                                    |
|-------------------|-----------------------------------------|-----------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
|`PowerShellCommand`|4688 (process creation of powershell.exe)|4103 / 4104|4104 = script block logging (the high-value one — captures de-obfuscated script content). 4103 = module logging. Both require explicit policy enablement.|

### Account and group changes (local)

|ActionType                        |Security                                       |Notes                                                |
|----------------------------------|-----------------------------------------------|-----------------------------------------------------|
|`UserAccountCreated`              |4720                                           |                                                     |
|`UserAccountDeleted`              |4726                                           |                                                     |
|`UserAccountModified`             |4738                                           |Generic “account changed” — sub-fields indicate what.|
|`UserAccountAddedToLocalGroup`    |4732                                           |                                                     |
|`UserAccountRemovedFromLocalGroup`|4733                                           |                                                     |
|`SecurityGroupCreated`            |4727 (global) / 4731 (local) / 4754 (universal)|                                                     |
|`SecurityGroupDeleted`            |4730 / 4734 / 4758                             |                                                     |

For **domain** account changes, see `IdentityDirectoryEvents` (MDI) — same event
IDs but logged on DCs.

### Credentials

|ActionType                                                 |Sysmon                       |Notes                                                                            |
|-----------------------------------------------------------|-----------------------------|---------------------------------------------------------------------------------|
|`LocalSecurityAuthoritySubsystemServiceProcessAccessDenied`|10 (target=lsass.exe, denied)|Tamper-protection-blocked LSASS access.                                          |
|`UntrustedExecutableLoadedByLsass`                         |7 (image load into lsass.exe)|Sysmon 7 + filter on `lsass.exe` as image-loading process catches similar signal.|
|`LdapSearch`                                               |—                            |Defender-derived; native LDAP query auditing is on the DC side.                  |

### Audit policy

|ActionType               |Security|Notes                                                                                   |
|-------------------------|--------|----------------------------------------------------------------------------------------|
|`AuditPolicyModification`|4719    |System audit policy changed. Critical to monitor — attackers disable auditing as a step.|
|(object SACL changed)    |4907    |Not surfaced as a distinct `DeviceEvents` ActionType.                                   |

### Removable media

|ActionType                  |Security|Kernel-PnP|Notes                                 |
|----------------------------|--------|----------|--------------------------------------|
|`UsbDriveMounted`           |6416    |400       |6416 = new external device recognised.|
|`UsbDriveUnmounted`         |—       |—         |Defender-derived.                     |
|`UsbDriveDriveLetterChanged`|—       |—         |Defender-derived.                     |
|`PnpDeviceConnected`        |6416    |400       |—                                     |

### Named pipes and SMB

|ActionType          |Sysmon                               |Security                     |Notes                                                                                                                              |
|--------------------|-------------------------------------|-----------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
|`NamedPipeEvent`    |17 (PipeCreated) / 18 (PipeConnected)|—                            |Sysmon 17/18 are the only native source.                                                                                           |
|`SmbSessionOpened`  |—                                    |5140 / 5145                  |5140 = network share accessed; 5145 = detailed share access (per-file). Requires “Audit Detailed File Share” or “Audit File Share”.|
|`SmbSessionDeletion`|—                                    |5140 (paired with disconnect)|—                                                                                                                                  |

### Defender-specific signal (no clean channel equivalent)

|ActionType                       |Source                                 |Notes                         |
|---------------------------------|---------------------------------------|------------------------------|
|`Asr*Audited` / `Asr*Blocked`    |`Defender-Op` 1121 / 1122              |ASR rule audit / block events.|
|`ExploitGuardChildProcessAudited`|`Defender-Op` various                  |Exploit Guard telemetry.      |
|`ControlFlowGuardViolation`      |—                                      |Defender-only.                |
|`SmartScreenAppWarning`          |`SmartScreen`                          |Operational-mode channel.     |
|`SmartScreenUrlWarning`          |`SmartScreen`                          |—                             |
|`SmartScreenUserOverride`        |`SmartScreen`                          |—                             |
|`TamperingAttempt`               |`Defender-Op` 5004 / 5007 / 5010 / 5012|Tamper protection events.     |
|`AmsiSampleContentRequest`       |`Defender-Op` (various)                |AMSI scan request telemetry.  |
|`BrowserLaunchedToOpenUrl`       |—                                      |Defender-derived from sensor. |

-----

## IdentityLogonEvents

(MDI required — events logged on monitored DCs.)

|ActionType / scenario          |Security (on DC)|Notes                                                                                |
|-------------------------------|----------------|-------------------------------------------------------------------------------------|
|Kerberos TGT request           |4768            |“Result code” field distinguishes success/failure types — pre-auth failure is `0x18`.|
|Kerberos service ticket request|4769            |Watch for `0x17` (RC4 — Kerberoasting signal) and unusual `Service Name`.            |
|Kerberos pre-auth failed       |4771            |AS-REP Roasting precursor when pre-auth disabled.                                    |
|NTLM credential validation     |4776            |“Source workstation” useful for relay detection.                                     |
|Logon at DC                    |4624 / 4625     |Same event IDs as endpoints, but DC-sourced.                                         |

-----

## IdentityDirectoryEvents

(MDI required.)

|ActionType / scenario     |Security (on DC)|Notes                                                                                                                                                                |
|--------------------------|----------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|Directory object created  |5137            |New user, group, OU, etc.                                                                                                                                            |
|Directory object modified |5136            |Attribute changes — high volume, filter by attribute.                                                                                                                |
|Directory object deleted  |5141            |—                                                                                                                                                                    |
|Directory object moved    |5139            |—                                                                                                                                                                    |
|Directory object operation|4662            |Generic — useful for DCSync detection when correlated with replication GUIDs (`{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` and `{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}`).|
|User account changes      |4720–4738       |Domain-side versions of the local account events listed under `DeviceEvents`.                                                                                        |

-----

## What’s *Defender-only* (no useful native event mapping)

Hunting these in Sentinel `SecurityEvent` or Splunk `wineventlog` won’t work —
they require MDE telemetry or a different log source entirely:

- All memory manipulation ActionTypes beyond `OpenProcess` / `CreateRemoteThread`
- Most HTTP/SSL inspection signal
- ASR rule triggers in normalised form (raw is in `Defender-Op` but not in Security)
- SmartScreen verdicts
- AMSI scan results
- Tamper protection events
- Defender XDR alert correlation (`AlertInfo` / `AlertEvidence`)
- Browser-launched-to-open-URL signal
- Exploit Guard verdicts

-----

## Cross-source hunt patterns

### “Process creation” — equivalent queries across sources

**Defender Advanced Hunting (MDE):**

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName == "powershell.exe"
```

**Sentinel `SecurityEvent` (4688):**

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| where NewProcessName endswith "\\powershell.exe"
```

**Sentinel `Event` (Sysmon 1):**

```kql
Event
| where TimeGenerated > ago(24h)
| where Source == "Microsoft-Windows-Sysmon" and EventID == 1
| parse EventData with * 'Image">' Image '<' *
| where Image endswith "\\powershell.exe"
```

**Splunk (Windows Security):**

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4688
New_Process_Name="*\\powershell.exe"
```

**Splunk (Sysmon):**

```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\powershell.exe"
```

### “Service installed” — same hunt, three sources

```kql
// MDE
DeviceEvents | where ActionType == "ServiceInstalled"

// Sentinel SecurityEvent
SecurityEvent | where EventID == 4697

// Sentinel WindowsEvent (System log 7045)
WindowsEvent | where EventID == 7045 and Channel == "System"
```

-----

## Caveats

- **Audit policy assumptions.** Every Security channel event listed assumes the
  relevant audit subcategory is enabled. In real environments, many aren’t.
  Check `auditpol /get /category:*` on a sample host before promising signal.
- **Sysmon configuration matters more than version.** A Sysmon install with the
  default empty config produces almost nothing. Reference SwiftOnSecurity or
  Olaf Hartong configs as a baseline.
- **MDE sensor version dependent.** Newer ActionTypes (especially in
  `DeviceEvents`) require recent sensor versions. Old endpoints under-report.
- **Mapping evolves.** This file is a guide, not gospel. When in doubt, run
  parallel queries and compare row counts.

-----

*Last reviewed: 2026-05-27. Built as a cross-reference aid for the Defender
Telemetry agent.*