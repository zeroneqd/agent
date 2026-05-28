# Defender XDR Advanced Hunting — Schema Overview

> **Purpose.** Use this file to shortlist candidate tables before drilling into the
> per-table reference under `docs/advanced-hunting/`. Each entry lists what the table
> actually captures, the most useful `ActionType` values, the platforms it covers,
> and — most importantly — the **known telemetry gaps** so you don’t confidently
> claim something is logged when it isn’t.

## How to use this file

1. **Shortlist 2–3 candidate tables** by reading the **Logs** line in each section.
1. **Always check the Gaps line** before answering — most “is X logged?” mistakes
   come from assuming Windows-level coverage exists on Linux, in containers, or
   for kernel-initiated activity.
1. **Confirm columns and exact `ActionType` strings** against the per-table
   markdown in `docs/advanced-hunting/` — those files are the authoritative source
   pulled from `MicrosoftDocs/defender-docs`.
1. **Treat ActionType lists as non-exhaustive.** New ActionTypes appear regularly,
   especially in `DeviceEvents`. When uncertain, propose a verification KQL that
   summarises `ActionType` values seen in the last 7 days.
1. **Always verify against your tenant’s schema** for the final answer — the live
   `FetchAdvancedHuntingTablesDetailedSchema` view in the Defender portal is
   authoritative; this file is a shortlist aid.

-----

## Microsoft Defender for Endpoint (MDE) — device telemetry

### DeviceProcessEvents

- **Source:** MDE sensor (Windows, macOS, Linux)
- **Logs:** process creation events — image path, command line, parent process
  chain, token elevation, integrity level, image signing info, account context,
  process IDs, file hashes
- **Common ActionTypes:** `ProcessCreated` (primary). Most process-related signal
  beyond creation lives in `DeviceEvents`.
- **Platforms:** Windows full; macOS partial; Linux partial
- **Gaps:**
  - Linux: no Windows-style integrity level; some short-lived processes via
    `execveat` paths may not be captured consistently
  - Kernel-mode-initiated processes (driver-spawned) frequently invisible
  - WSL2 guest processes only visible if the MDE WSL plugin is deployed
  - Container processes: only visible if the host MDE sensor sees them; not all
    container runtimes surface child processes reliably
  - Process injection rarely shows here — see `DeviceEvents` (`CreateRemoteThreadApiCall`,
    `WriteProcessMemoryApiCall`, `NtAllocateVirtualMemoryRemoteApiCall`)

### DeviceFileEvents

- **Source:** MDE sensor
- **Logs:** file create, modify, rename, delete, copy; SHA1/SHA256/MD5 hashes;
  previous file name on rename; folder paths; initiating process context
- **Common ActionTypes:** `FileCreated`, `FileModified`, `FileRenamed`, `FileDeleted`,
  `FileCopied` (Windows)
- **Platforms:** Windows full; Linux limited; macOS partial
- **Gaps:**
  - Linux: `FileModified` coverage is sparse on many filesystems; relies on
    fanotify/inotify hooks that miss some I/O paths
  - Memory-mapped writes (`MapViewOfFile`) frequently invisible on Windows too
  - Alternate Data Streams: partial — ADS create/write often not surfaced as
    distinct events
  - Volume Shadow Copy interactions sparse — vssadmin activity better caught via
    `DeviceProcessEvents` + command line
  - Very high-volume paths (browser caches, build outputs) may be sampled/excluded
    by sensor config
  - Network filesystem writes (SMB, NFS) — initiating side may not surface as
    `FileCreated` reliably

### DeviceRegistryEvents

- **Source:** MDE sensor (Windows only)
- **Logs:** registry key/value create, modify, delete, rename; previous values on
  modify; initiating process context
- **Common ActionTypes:** `RegistryKeyCreated`, `RegistryKeyDeleted`,
  `RegistryKeyRenamed`, `RegistryValueSet`, `RegistryValueDeleted`
- **Platforms:** Windows only
- **Gaps:**
  - Transacted registry operations may not surface until commit
  - Containerised app writes to virtualised HKCU hives — visibility varies
  - High-volume keys (e.g. some performance counters) sampled by sensor
  - `Reg.exe` and PowerShell `Set-ItemProperty` activity also visible in
    `DeviceProcessEvents` command lines — useful corroboration
  - Registry reads (`RegistryQueryValue`) generally NOT logged — only writes

### DeviceNetworkEvents

- **Source:** MDE sensor
- **Logs:** outbound and inbound network connections, DNS lookups (some),
  HTTP/HTTPS metadata, listening sockets opened, initiating process context;
  remote IP, remote port, protocol
- **Common ActionTypes:** `ConnectionSuccess`, `ConnectionFailed`,
  `ConnectionAttempt`, `InboundConnectionAccepted`, `ListeningConnectionCreated`,
  `DnsConnectionInspected`, `HttpConnectionInspected`, `SslConnectionInspected`,
  `IcmpConnectionRequest`
- **Platforms:** Windows full; Linux partial; macOS partial
- **Gaps:**
  - Linux: process attribution on connections sometimes missing or stale
  - Loopback traffic generally NOT logged
  - Raw socket activity (BPF, AF_PACKET, AF_ALG) usually invisible — these
    bypass standard socket telemetry
  - VPN tunnels: only the underlying connection is visible, not encapsulated flows
  - Containerised network namespaces — visibility varies; CNI plugin traffic
    often opaque
  - DNS over HTTPS (DoH) appears as encrypted HTTPS only; queries not parsed

### DeviceLogonEvents

- **Source:** MDE sensor
- **Logs:** interactive, network, remote interactive, batch, service, unlock logons
  on Windows endpoints; success and failure; account, logon type, IP
- **Common ActionTypes:** `LogonSuccess`, `LogonFailed`, `LogonAttempted`
- **Platforms:** Windows primary; Linux limited; macOS limited
- **Gaps:**
  - Linux/macOS coverage focuses on a subset of logon paths (SSH, console);
    coverage of PAM events, sudo elevations, su transitions inconsistent
  - Kerberos authentication events on DCs surface in `IdentityLogonEvents`, not
    here
  - Service account context switches via Run As / `runas.exe` partial
  - For pre-authentication Kerberos failures and ticket events, see
    `IdentityLogonEvents` and `IdentityDirectoryEvents` (MDI required)

### DeviceImageLoadEvents

- **Source:** MDE sensor
- **Logs:** DLL/module image loads — image path, hash, signer, loading process
- **Common ActionTypes:** `ImageLoaded`
- **Platforms:** Windows primary; Linux/macOS partial
- **Gaps:**
  - Reflective DLL loads (loaded from memory, never written to disk) typically
    invisible — partial signal via `DeviceEvents` API call ActionTypes
  - Some Microsoft-signed system DLLs deliberately excluded by sensor config
    for volume reasons
  - Module Stomping / Hollowing detection requires correlation with
    `DeviceEvents` memory ActionTypes
  - Linux `dlopen`-style loads — coverage is partial and library-dependent
  - Driver loads tracked separately in `DeviceEvents` (`DriverLoad`,
    `KernelModuleLoad` on Linux)

### DeviceEvents

- **Source:** MDE sensor — catch-all for “everything else”
- **Logs:** the largest and most varied table. Captures API call telemetry,
  ASR rule triggers, security feature triggers, AMSI events, tamper attempts,
  driver loads, kernel module loads, scheduled task changes, service installs,
  WMI subscriptions, USB events, screenshot/keylog-adjacent signals,
  PowerShell command execution, and many more
- **Common ActionType families:**
  - **Process injection / memory:** `OpenProcessApiCall`, `OpenThreadApiCall`,
    `CreateRemoteThreadApiCall`, `WriteProcessMemoryApiCall`,
    `ReadProcessMemoryApiCall`, `NtAllocateVirtualMemoryApiCall`,
    `NtAllocateVirtualMemoryRemoteApiCall`, `NtProtectVirtualMemoryApiCall`,
    `NtProtectVirtualMemoryRemoteApiCall`, `MemoryRemoteProtect`
  - **Drivers / kernel:** `DriverLoad`, `KernelModuleLoad` (Linux),
    `BpfFilterAttached` (Linux)
  - **Persistence:** `ScheduledTaskCreated`, `ScheduledTaskUpdated`,
    `ScheduledTaskDeleted`, `ServiceInstalled`, `WmiBindEventFilterToConsumer`,
    `ShellLinkCreateFileEvent`
  - **Account / group:** `UserAccountCreated`, `UserAccountDeleted`,
    `UserAccountModified`, `UserAccountAddedToLocalGroup`,
    `UserAccountRemovedFromLocalGroup`, `SecurityGroupCreated`,
    `SecurityGroupDeleted`
  - **Credentials:** `LocalSecurityAuthoritySubsystemServiceProcessAccessDenied`,
    `UntrustedExecutableLoadedByLsass`, `LdapSearch`
  - **PowerShell / scripting:** `PowerShellCommand`,
    `AmsiSampleContentRequest`
  - **ASR rules:** many `Asr*Audited` / `Asr*Blocked` variants
  - **Exploit Guard:** `ExploitGuardChildProcessAudited`,
    `ControlFlowGuardViolation`
  - **USB / removable media:** `UsbDriveMounted`, `UsbDriveUnmounted`,
    `UsbDriveDriveLetterChanged`, `PnpDeviceConnected`
  - **SmartScreen:** `SmartScreenAppWarning`, `SmartScreenUrlWarning`,
    `SmartScreenUserOverride`
  - **Tamper:** `TamperingAttempt`
  - **Named pipes / SMB:** `NamedPipeEvent`, `SmbSessionOpened`,
    `SmbSessionDeletion`
  - **Browser:** `BrowserLaunchedToOpenUrl`
- **Platforms:** Windows broadest; Linux narrower (kernel module, eBPF, some
  audit-derived events); macOS narrowest
- **Gaps:**
  - ActionType set evolves frequently — always verify currently-available values
    by summarising `ActionType` over the last 7 days
  - Linux: most Windows-specific ActionTypes (ASR, Exploit Guard, AMSI, SmartScreen,
    WMI) are absent by design
  - Container runtimes: kernel events visible to host but attribution to specific
    container often missing
  - Sensor version dependent — older MDE clients miss newer ActionTypes
  - High-volume ActionTypes occasionally sampled

### DeviceFileCertificateInfo

- **Source:** MDE sensor
- **Logs:** Authenticode signature info for files observed on devices — signer,
  issuer, certificate validity, signature state
- **Platforms:** Windows primary
- **Gaps:**
  - Only files MDE has scanned/observed — not a complete cert inventory
  - Linux ELF signatures not surfaced
  - Catalog-signed files: signer info present but path provenance can be confusing

### DeviceInfo

- **Source:** MDE sensor / Defender XDR inventory
- **Logs:** device identity, OS version, machine group, sensor health, public IP,
  logged-on users, AAD device ID, onboarding state — one row per snapshot
- **Platforms:** all onboarded devices
- **Use:** join target for enriching device-scoped events; not an event table
  — query with `summarize arg_max(Timestamp, *)` for current state

### DeviceNetworkInfo

- **Source:** MDE sensor
- **Logs:** network adapter inventory — MAC, IP addresses, DNS suffix, connected
  networks; snapshots, not events
- **Use:** correlating private IPs to devices for IR; not for detecting actions

### DeviceTvmSoftwareInventory

- **Source:** Defender Vulnerability Management
- **Logs:** software installed on each device, including version and end-of-support
- **Use:** vulnerability hunting and exposure assessment; snapshot data
- **Gaps:** Linux/macOS inventory less granular than Windows; some software
  detected by file presence rather than installer registration

### DeviceTvmSoftwareVulnerabilities

- **Source:** Defender Vulnerability Management
- **Logs:** CVE → device → software mapping with CVSS, exposure level
- **Use:** “which of our devices is vulnerable to CVE-X” hunts

### DeviceTvmSecureConfigurationAssessment

- **Source:** Defender Vulnerability Management
- **Logs:** security configuration findings per device (e.g. weak settings,
  missing protections), one row per (device, configuration)
- **Use:** posture hunting and exposure baseline checks

### DeviceTvmHardwareFirmware

- **Source:** Defender Vulnerability Management
- **Logs:** hardware and firmware inventory per device (BIOS/UEFI versions,
  processor, manufacturer)
- **Use:** firmware-level vulnerability and supply-chain hunting

-----

## Microsoft Defender for Identity (MDI) — on-prem AD / hybrid

### IdentityLogonEvents

- **Source:** MDI sensor on domain controllers + AAD Connect server
- **Logs:** authentication events visible at the DC — Kerberos, NTLM,
  interactive logons originating from monitored DCs; remote IP, account, target
- **Common ActionTypes:** `LogonSuccess`, `LogonFailed`, plus specific ones for
  Kerberos / NTLM contexts
- **Platforms:** Windows DCs with MDI sensor
- **Gaps:**
  - Requires MDI deployment on DCs — coverage is per-DC, missing one DC leaves a hole
  - Authentication that never touches a monitored DC (workgroup machines, pure
    AAD-joined logons) doesn’t appear here — see `AADSignInEventsBeta`
  - Service ticket misuse (Golden / Silver) requires correlation with
    `IdentityDirectoryEvents`

### IdentityDirectoryEvents

- **Source:** MDI
- **Logs:** AD changes and system events on DCs — password changes, UPN changes,
  password expiration, account lockouts, scheduled tasks on DCs, PowerShell
  activity on DCs, DCSync attempts, replication events
- **Platforms:** Windows DCs with MDI sensor
- **Gaps:**
  - Pure AAD/Entra-only changes — see `CloudAppEvents` / Entra audit logs
  - Read-only LDAP queries — see `IdentityQueryEvents`

### IdentityQueryEvents

- **Source:** MDI
- **Logs:** LDAP and SAMR queries hitting DCs — reconnaissance signals
  (BloodHound-style enumeration), object-of-interest queries
- **Use:** detecting AD reconnaissance
- **Gaps:**
  - Queries that don’t traverse a monitored DC are invisible
  - High volume — needs thoughtful filtering

### IdentityInfo

- **Source:** unified identity inventory (MDI + Entra ID)
- **Logs:** user identity snapshot — UPN, account names, group membership, risk
  level, account creation, sensitive account flag
- **Use:** join target for identity enrichment; snapshot data, not events

-----

## Microsoft Defender for Office 365 (MDO) — email and Teams

### EmailEvents

- **Source:** MDO
- **Logs:** every email processed — sender, recipients, subject, attachments,
  authentication results (SPF/DKIM/DMARC), delivery action, threat verdict
- **Platforms:** Exchange Online with MDO
- **Gaps:** on-prem Exchange email not covered; only post-MDO-scan view

### EmailAttachmentInfo

- **Source:** MDO
- **Logs:** attachment metadata per email — file name, type, hash, threat verdict
- **Use:** payload hunting across email

### EmailUrlInfo

- **Source:** MDO
- **Logs:** URLs extracted from emails — one row per (email, URL)
- **Use:** indicator hunting against email-borne URLs

### EmailPostDeliveryEvents

- **Source:** MDO (Zero-hour Auto Purge, manual remediation)
- **Logs:** actions taken on already-delivered email — ZAP removals, soft deletes
- **Use:** IR timeline of remediation actions
- **Gaps:** only post-delivery action records, not original delivery

### UrlClickEvents

- **Source:** MDO Safe Links
- **Logs:** click-through events on Safe Links–wrapped URLs — clicked URL,
  account, verdict at click time, action taken
- **Platforms:** users protected by Safe Links policies
- **Gaps:**
  - URLs from unprotected sources or copied out of email won’t be wrapped
  - Direct browser visits don’t appear here — see `DeviceNetworkEvents`

### MessageEvents

- **Source:** MDO for Microsoft Teams
- **Logs:** Teams messages — sender, recipient(s), content metadata, attachments,
  URLs, threat verdict
- **Gaps:** scope limited to MDO-protected tenants; external federated chats
  coverage varies

### MessagePostDeliveryEvents

- **Source:** MDO for Teams
- **Logs:** post-delivery actions on Teams messages — ZAP, manual remediation

### MessageUrlInfo

- **Source:** MDO for Teams
- **Logs:** URLs extracted from Teams messages

-----

## Microsoft Defender for Cloud Apps (MDCA) — SaaS / cloud

### CloudAppEvents

- **Source:** MDCA connectors + Microsoft Graph activity
- **Logs:** activity across connected SaaS apps (M365, Salesforce, ServiceNow,
  GitHub, etc.) — sign-ins, file access, sharing, admin changes, mass downloads.
  Also captures **AI agent activity** (tool invocations, MCP server executions,
  inference calls) for tenants with Agent 365 / Work IQ enabled.
- **Common ActionType families:**
  - File / sharing: `FileAccessed`, `FileDownloaded`, `FileUploaded`,
    `FileShared`, `FilePermissionChanged`
  - Account: `Add user`, `Change user password`, `Update user`
  - Admin: tenant-specific provisioning, role assignment, policy changes
  - Agent: AI agent tool calls and MCP executions (newer)
- **Platforms:** SaaS apps connected via API connector or session control
- **Gaps:**
  - API connector coverage varies by app — read the connector capability matrix
  - Latency: some apps surface events with hours of delay
  - Session control (reverse proxy) sees a different subset than API connector

### AADSignInEventsBeta

- **Source:** Entra ID sign-in logs (preview table)
- **Logs:** interactive and non-interactive user sign-ins, MFA results,
  conditional access result, risk state, IP, device, app, location
- **Gaps:**
  - **Beta table** — schema may change; lags GA sign-in logs in some fields
  - Service principal sign-ins NOT here — use `AADSpnSignInEventsBeta`
  - Token replays via refresh tokens may not surface as fresh sign-ins —
    correlate with CAE and risk events separately

### AADSpnSignInEventsBeta

- **Source:** Entra ID sign-in logs (service principals)
- **Logs:** application and managed identity sign-ins
- **Use:** detecting abused service principals, anomalous app token use
- **Gaps:** beta table; cross-tenant SPN activity attribution can be confusing

-----

## XDR-wide — alerts and correlation

### AlertInfo

- **Source:** Defender XDR — alerts from all workloads (MDE, MDO, MDI, MDCA,
  AAD Identity Protection)
- **Logs:** one row per alert — title, severity, category, MITRE technique,
  status, classification, determination
- **Use:** alert-driven hunting; pivoting from a triaged alert into raw telemetry

### AlertEvidence

- **Source:** Defender XDR
- **Logs:** entities associated with each alert — files, processes, devices,
  users, IPs, URLs, mailboxes — one row per (alert, entity)
- **Use:** join target between `AlertInfo` and raw event tables; entity-based
  hunting

-----

## Exposure Management (newer)

### ExposureGraphNodes

- **Source:** Microsoft Security Exposure Management
- **Logs:** entities in the exposure graph — devices, identities, cloud
  resources, apps — with risk attributes
- **Use:** attack path analysis and choke-point identification

### ExposureGraphEdges

- **Source:** Microsoft Security Exposure Management
- **Logs:** relationships between nodes — “can authenticate as”, “is admin of”,
  “has access to” — directed edges
- **Use:** graph-based hunting; combine with `ExposureGraphNodes` to traverse
  attack paths

-----

## Quick scenario → table map

|Question                             |Start here                                           |Often correlated with                                  |
|-------------------------------------|-----------------------------------------------------|-------------------------------------------------------|
|Did a process run?                   |`DeviceProcessEvents`                                |`DeviceImageLoadEvents`                                |
|Was a file dropped / modified?       |`DeviceFileEvents`                                   |`DeviceProcessEvents` (initiator)                      |
|Was a registry key written?          |`DeviceRegistryEvents`                               |`DeviceProcessEvents`                                  |
|Did this device beacon out?          |`DeviceNetworkEvents`                                |`DeviceProcessEvents`                                  |
|Was a DLL loaded?                    |`DeviceImageLoadEvents`                              |`DeviceEvents` (for reflective)                        |
|Was a driver / kernel module loaded? |`DeviceEvents` (`DriverLoad`, `KernelModuleLoad`)    |`DeviceImageLoadEvents`                                |
|Process injection?                   |`DeviceEvents` (memory / remote-thread ActionTypes)  |`DeviceProcessEvents`                                  |
|PowerShell command run?              |`DeviceEvents` (`PowerShellCommand`)                 |`DeviceProcessEvents`                                  |
|Scheduled task / service persistence?|`DeviceEvents` (`ScheduledTask*`, `ServiceInstalled`)|`DeviceProcessEvents`                                  |
|Named pipe activity?                 |`DeviceEvents` (`NamedPipeEvent`)                    |`DeviceProcessEvents`                                  |
|User logged on to endpoint?          |`DeviceLogonEvents`                                  |`DeviceProcessEvents`                                  |
|User authenticated against AD?       |`IdentityLogonEvents`                                |`IdentityDirectoryEvents`                              |
|Entra ID user sign-in?               |`AADSignInEventsBeta`                                |`IdentityInfo`                                         |
|Service principal sign-in?           |`AADSpnSignInEventsBeta`                             |—                                                      |
|AD reconnaissance (LDAP / SAMR)?     |`IdentityQueryEvents`                                |`IdentityDirectoryEvents`                              |
|Phishing email landed?               |`EmailEvents`                                        |`EmailAttachmentInfo`, `EmailUrlInfo`, `UrlClickEvents`|
|User clicked a malicious link?       |`UrlClickEvents`                                     |`DeviceNetworkEvents`                                  |
|SaaS app abuse (M365, GitHub, etc.)? |`CloudAppEvents`                                     |`AADSignInEventsBeta`                                  |
|AI agent tool / MCP execution?       |`CloudAppEvents`                                     |—                                                      |
|What alerted, and on what entity?    |`AlertInfo` + `AlertEvidence`                        |join into raw event tables                             |
|Vulnerable software present?         |`DeviceTvmSoftwareInventory`                         |`DeviceTvmSoftwareVulnerabilities`                     |

-----

## Linux-specific awareness

When the question targets Linux, the answer is more often “partial” or “no” than
people expect. Useful priors before answering:

- **Process creation:** `DeviceProcessEvents` works, but no integrity level
  concept; some short-lived process churn missed
- **File events:** `FileModified` coverage is sparse on most filesystems
- **Registry events:** N/A
- **Kernel modules:** `DeviceEvents` (`KernelModuleLoad`) — useful for rootkit hunting
- **eBPF:** partial via `DeviceEvents` (`BpfFilterAttached`); kernel-internal
  eBPF program loads from unprivileged paths often missed
- **Syscall-level telemetry:** generally not surfaced — auditd-style coverage is
  not what MDE provides
- **Kernel exploit primitives** (AF_ALG, splice, page-cache manipulation,
  esp4/esp6/rxrpc paths): typically invisible. Detection usually has to come from
  *post-exploitation* behaviour (unexpected SUID processes, root shell parented
  by user process, kernel module appearance), not the exploit itself
- **Container escapes:** host-side process and file events visible *if* they
  cross the namespace boundary; many escape primitives complete entirely in-kernel
  before producing host-visible signal
- **SUDO / SU / PAM:** partial; `DeviceProcessEvents` will show the binary
  execution, but PAM session events are not consistently surfaced

When in doubt for Linux questions: answer “not directly surfaced — recommend
verification via `DeviceEvents | where DeviceId == ... | summarize count() by ActionType` over a known-good window, or post-exploitation behavioural hunt.”

-----

## Common KQL plumbing reminders

- **Default lookback:** `Timestamp > ago(24h)` unless the hunt needs longer
- **Join keys:** `DeviceId` for device tables; `DeviceId` + `ReportId` for
  process ancestry joins to deduplicate; `AccountObjectId` for cross-identity
- **ActionType filters:** case-sensitive — `ActionType == "ProcessCreated"`
  not `"processcreated"`
- **String matching:** prefer `has`, `has_any`, `has_cs` over `contains` on
  high-cardinality columns for performance
- **Process ancestry:** use `InitiatingProcess*` columns first; walk further
  back via `InitiatingProcessParentFileName` etc. — for deeper ancestry, join
  `DeviceProcessEvents` to itself on `DeviceId` + `InitiatingProcessId` +
  `InitiatingProcessCreationTime`
- **Project useful columns only** — wide projections hurt performance and
  readability

-----

*Last reviewed: 2026-05-27. Schema evolves — verify ActionType availability
against the live `FetchAdvancedHuntingTablesDetailedSchema` view in the Defender
portal before deploying detections.*