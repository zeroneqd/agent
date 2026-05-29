# Windows Security Audit Events Reference

> **Purpose.** Per-event-ID reference for the Windows `Security` event log — the
> foundational audit channel that every Windows endpoint and domain controller
> produces. Use this to:
>
> - Translate MDE hunts into Sentinel `SecurityEvent` queries or Splunk
>   `wineventlog:Security` searches
> - Understand prerequisites (SACLs, audit policies) before promising signal exists
> - Identify Security-only signals that MDE doesn't surface
> - Cross-reference with Sysmon and MDE for multi-source hunts

## Before reading

- **Security events are policy-dependent.** Unlike Sysmon (config-driven) or MDE
  (sensor-driven), Security channel events require specific Advanced Audit
  Configuration subcategories to be enabled. No policy = no events.
- **Channel name:** `Security` (Windows Event Log → Security)
- **Sentinel ingestion:** `SecurityEvent` table (legacy) or `WindowsEvent` table
  (newer AMA agent). Field names differ — `SecurityEvent` uses `EventID` and
  `NewProcessName`; `WindowsEvent` uses `EventID` and requires XML parsing.
- **Splunk ingestion:** `source=wineventlog` `sourcetype=wineventlog:security` or
  `sourcetype=XmlWinEventLog:Security`
- **High-volume events** (4688, 4663, 5156) need careful filtering — full
  collection without tuning can overwhelm SIEM ingest.

-----

## Quick-enable reference

Enable via Group Policy (`gpmc.msc`) or local security policy (`secpol.msc`):

```
Computer Configuration → Windows Settings → Security Settings →
  Advanced Audit Policy Configuration → System Audit Policies
```

Or via command line (`auditpol`):
```cmd
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

Verify what's actually enabled:
```cmd
auditpol /get /category:*
```

-----

## Authentication & Logon

### Event ID 4624 — An account was successfully logged on

**Captures:** every successful Windows logon — interactive, network, service, batch,
unlock, remote interactive.

**Key fields:**

- `SubjectUserName`, `SubjectDomainName` — the authenticating account
- `TargetUserName`, `TargetDomainName` — the account being logged on
- `LogonType` — **critical field**: 2 (interactive), 3 (network), 4 (batch),
  5 (service), 7 (unlock), 8 (network cleartext), 9 (new credentials), 10 (remote
  interactive / RDP), 11 (cached interactive)
- `IpAddress` — source IP (empty for local)
- `IpPort` — source port
- `AuthenticationPackageName` — `NTLM`, `Kerberos`, `Negotiate`
- `LmPackageName` — for NTLM: `NTLM V1`, `NTLM V2`
- `ProcessName` — process that authenticated (e.g., `C:\Windows\System32\svchost.exe`)
- `KeyLength` — session key length (0 = no encryption)

**Detection use:**

- Lateral movement: LogonType 3 from unexpected IPs, atypical service accounts
- RDP sessions: LogonType 10 from unusual sources
- Pass-the-hash: LogonType 3 + `AuthenticationPackageName == "NTLM"` + null `LmPackageName`
- Service abuse: LogonType 5 from unexpected service accounts
- Admin-equivalent logon: correlate with 4672

**Gotchas:**

- **Very high volume.** LogonType 3 (network) fires constantly from file shares,
  RPC, WMI. Filter aggressively by account type, IP range, or time.
- **IP field can be empty** for local logons and some service logons.
- **Every service start produces a 4624 LogonType 5** — high baseline noise.
- **No SubjectUserName on some NTLM authentications** — field may be `ANONYMOUS LOGON`.

**Prerequisites:** Advanced Audit → Logon → Success

**MDE equivalent:** `DeviceLogonEvents` (`ActionType == "LogonSuccess"`).

**Sentinel:** `SecurityEvent | where EventID == 4624`

**Splunk:** `index=wineventlog EventCode=4624`

-----

### Event ID 4625 — An account failed to log on

**Captures:** every failed logon attempt.

**Key fields:** Same as 4624 plus:

- `Status` — NTSTATUS code: `0xC0000064` (no such user), `0xC000006A` (bad password),
  `0xC0000234` (account locked out), `0xC0000072` (disabled), `0xC000006F`
  (outside logon hours), `0xC0000071` (expired password)
- `SubStatus` — additional detail; `0xC0000071` (expired), `0xC0000413`
  (restricted logon type)

**Detection use:**

- Brute-force: repeated 4625 from single IP targeting one or multiple accounts
- Password spray: 4625 with many `TargetUserName` values from single source
- Kerberoasting precursor: 4625 with `Status == 0xC0000064` for fake service accounts
- Account enumeration: systematic 4625 across username space
- Lockout triage: `0xC0000234` reveals which accounts are locked

**Gotchas:**

- **NLA/RDP pre-authentication generates 4625 before the real logon** — not every
  4625 is an attack.
- **SSO misconfigurations generate massive 4625 volume** — baseline before alerting.
- `Status` and `SubStatus` are hex strings — parse carefully in KQL/SPL.

**Prerequisites:** Advanced Audit → Logon → Failure

**MDE equivalent:** `DeviceLogonEvents` (`ActionType == "LogonFailed"`).

-----

### Event ID 4634 — An account was logged off

**Captures:** logoff event.

**Key fields:** `TargetUserName`, `TargetDomainName`, `LogonType`

**Detection use:** timeline completeness — pair with 4624 to compute session duration.

**Gotchas:** not every 4624 has a matching 4634 (system shutdown, crash, forced logoff).

**Prerequisites:** Advanced Audit → Logoff → Success

**MDE equivalent:** none — MDE doesn't log process termination or logoff directly.

-----

### Event ID 4647 — User initiated logoff

**Captures:** user manually logged off.

**Detection use:** IR timeline — distinguishes intentional logoff from forced/session timeout.

**Prerequisites:** Advanced Audit → Logoff → Success

**MDE equivalent:** none.

-----

### Event ID 4648 — A logon was attempted using explicit credentials

**Captures:** `runas.exe`, scheduled task execution, service startup with explicit
 credentials, RDP with saved credentials — any situation where credentials are
 supplied for a secondary logon.

**Key fields:**

- `SubjectUserName` — the account initiating
- `TargetUserName` — the account whose credentials were used
- `TargetServerName` — the destination system
- `IpAddress` — destination IP
- `ProcessName` — process that initiated (e.g., `runas.exe`, `taskeng.exe`)

**Detection use:**

- Lateral movement: `runas` to remote system with admin credentials
- Scheduled task abuse: unusual `TargetUserName` from `svchost.exe` (Task Scheduler)
- Credential theft follow-on: adversary using harvested creds via `runas`

**Gotchas:**

- **Legitimate scheduled tasks fire this constantly** — baseline by `ProcessName`
  and `TargetUserName` before alerting.
- **Saved RDP credentials produce 4648 at every connection.**

**Prerequisites:** Advanced Audit → "Audit Other Logon/Logoff Events" → Success

**MDE equivalent:** none direct — closest is `DeviceLogonEvents` correlated with
`DeviceProcessEvents` for `runas.exe` invocations.

-----

### Event ID 4672 — Special privileges assigned to new logon

**Captures:** admin-equivalent logon — any logon where the account holds
"administrator-equivalent" privileges (e.g., local Administrators, Domain Admins,
Account Operators).

**Key fields:**

- `SubjectUserName`, `SubjectDomainName`
- `PrivilegeList` — e.g., `SeDebugPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`,
  `SeTakeOwnershipPrivilege`, `SeTcbPrivilege`

**Detection use:**

- Admin-equivalent logon tracking — every 4672 should have a known owner
- `SeDebugPrivilege` abuse — enables memory access to any process (LSASS dumping)

**Gotchas:**

- **Fires alongside 4624** — every admin logon produces both. Use 4672 to filter
  4624 down to privileged sessions only.
- **Volume proportional to admin population** — in large estates with many admins,
  this is very noisy. Filter by time-of-day, source IP, or service account.

**Prerequisites:** Advanced Audit → "Audit Special Logon" → Success

**MDE equivalent:** none — no privilege-level granularity in `DeviceLogonEvents`.

-----

### Event ID 4778 — A session was reconnected to a Window Station

**Captures:** RDP session reconnection (user reconnects to an existing session).

**Detection use:** track RDP session persistence — reconnections from unexpected IPs.

**Prerequisites:** Advanced Audit → "Audit Other Logon/Logoff Events" → Success

-----

### Event ID 4779 — A session was disconnected from a Window Station

**Captures:** RDP session disconnect.

**Detection use:** pair with 4778 to track RDP session lifecycle.

**Prerequisites:** Advanced Audit → "Audit Other Logon/Logoff Events" → Success

-----

## Process Activity

### Event ID 4688 — A new process has been created

**Captures:** every process start (when enabled).

**Key fields:**

- `SubjectUserName`, `SubjectDomainName` — the account that started the process
- `NewProcessName` — full path to the executable
- `ProcessCommandLine` — **requires separate policy enablement**:
  `Computer Configuration → Administrative Templates → System → Audit Process
  Creation → Include command line in process creation auditing events`
- `TokenElevationType` — `%%1936` (limited), `%%1937` (full — UAC elevated),
  `%%1938` (default)
- `TargetLogonId` — correlates back to the originating 4624

**Detection use:**

- LOLBin abuse: `certutil.exe`, `bitsadmin.exe`, `mshta.exe`, `regsvr32.exe` with
  suspicious command lines
- Suspicious parent-child: `cmd.exe` spawning `powershell.exe`, `winword.exe` spawning
  `cmd.exe`
- Renamed binaries: `svchost.exe` running from non-`System32` path
- UAC bypass: `TokenElevationType == "%%1937"` from unexpected processes

**Gotchas:**

- **Command line logging is NOT enabled by default.** Without it, 4688 is just
  `NewProcessName` — far less useful. Always verify command line policy is enabled
  before promising command-line signal.
- **Very high volume** — every process start generates this. Plan SIEM ingest
  accordingly.
- **Field name varies by ingestion path:** Sentinel `SecurityEvent` uses
  `NewProcessName`; raw XML uses `NewProcessName`; Splunk uses `New_Process_Name`.

**Prerequisites:**

- Advanced Audit → "Detailed Tracking → Process Creation" → Success
- Plus GPO: "Include command line in process creation auditing events" (for command line)

**MDE equivalent:** `DeviceProcessEvents` (`ActionType == "ProcessCreated"`).
MDE provides better process ancestry via `InitiatingProcess*` columns.

**Sentinel:**
```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "\\powershell.exe"
| where CommandLine has "-enc"
```

**Splunk:**
```spl
index=wineventlog EventCode=4688 New_Process_Name="*\\powershell.exe"
```

-----

### Event ID 4689 — A process has exited

**Captures:** process termination.

**Key fields:** `SubjectUserName`, `ProcessName`, `Status` — exit code (`0x0` = clean exit)

**Detection use:** pair with 4688 to compute process lifetime. Short-lived processes
(`4688` followed rapidly by `4689`) can indicate malicious tooling.

**Gotchas:**

- **MDE has no process termination event** — this is a Security-only signal useful
  for filling that gap.
- Volume is proportional to 4688 — very high.

**Prerequisites:** Advanced Audit → "Detailed Tracking → Process Termination" → Success

**MDE equivalent:** none — this is a gap in MDE. Sysmon Event 5 is the alternative.

-----

## Object Access (File, Registry, Kernel)

### Event ID 4663 — An attempt was made to access an object

**Captures:** access to files, folders, registry keys, or kernel objects that have
an explicit SACL applied.

**Key fields:**

- `SubjectUserName` — who accessed it
- `ObjectServer` — `Security`
- `ObjectType` — `File`, `Key` (registry), `Directory`
- `ObjectName` — full path to the file/registry key
- `AccessMask` — type of access: `0x10000` (DELETE), `0x40000` (WRITE_DAC),
  `0x80000` (WRITE_OWNER), `0x6` (read+write), `0x100000` (SYNCHRONIZE)
- `ProcessName` — process that performed the access

**Detection use:**

- Sensitive file access: when SACLs are applied to `NTDS.dit`, SAM hive backup,
  certificate stores, credential manager files
- Registry tampering: access to `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\`
- Anti-forensics: access to Volume Shadow Copy paths

**Gotchas:**

- **Requires explicit SACLs on every target object.** Most environments do NOT
  have wide SACL deployment because the volume is overwhelming. Before promising
  4663 signal, verify SACLs exist on the paths the user cares about.
- **AccessMask parsing is painful** — it's a bitmask. The event description text
  (e.g., "WriteData") is easier to parse than the raw hex.
- **Volume explodes with broad SACLs** — plan for massive ingest if deploying
  file-system-wide SACLs.

**Prerequisites:**

- Advanced Audit → "Object Access → Audit File System" → Success
- Plus explicit SACLs on target files/folders/registry keys

**MDE equivalent:** `DeviceFileEvents` provides broader file signal without SACL
requirements. Prefer MDE for general file hunting; use 4663 only for specific
sensitive-path monitoring.

-----

### Event ID 4656 — A handle to an object was requested

**Captures:** handle request to a kernel object — fires before the actual access.

**Key fields:** `SubjectUserName`, `ObjectType`, `ObjectName`, `AccessMask`,
`ProcessName`

**Detection use:** precursor to 4663 — can catch attempted access even if the actual
operation is blocked. Useful for detecting access attempts to sensitive objects.

**Gotchas:** even higher volume than 4663 — handle requests are extremely frequent.

**Prerequisites:** Advanced Audit → "Object Access" → Success + SACLs

**MDE equivalent:** none — handle-level visibility is Security-channel only.

-----

### Event ID 4657 — A registry value was modified

**Captures:** registry value changes when the "Audit Registry" subcategory is enabled
and the target key has a SACL.

**Key fields:**

- `SubjectUserName`
- `ObjectName` — the full registry key path
- `ObjectValueName` — the value name that changed
- `OldValue` — previous value (extremely useful for forensics)
- `NewValue` — new value
- `ProcessName` — which process made the change

**Detection use:**

- Persistence detection: `Run`, `RunOnce`, `Image File Execution Options`, Services,
  Winlogon shell changes
- Defence tampering: Windows Defender exclusion additions, audit policy modifications
- Configuration drift: unauthorized Group Policy registry changes

**Gotchas:**

- **OldValue + NewValue are high-value forensic fields** that Sysmon Event 13 lacks
  (Sysmon 13 only captures the new value). This is a key reason to keep Security
  registry auditing even with Sysmon deployed.
- **Requires SACLs on target keys** — without them, only keys under specific
  audit policies fire.

**Prerequisites:**

- Advanced Audit → "Object Access → Audit Registry" → Success
- Plus SACLs on target registry keys

**MDE equivalent:** `DeviceRegistryEvents` (`RegistryValueSet`). MDE captures all
registry writes without SACL requirements but doesn't provide `PreviousRegistryValueData`
 reliably.

-----

### Event ID 4660 — An object was deleted

**Captures:** deletion of a file, registry key, or directory with a SACL.

**Key fields:** `SubjectUserName`, `ObjectServer`, `ObjectType`, `ObjectName`,
`ProcessName`

**Detection use:** evidence destruction — deletion of sensitive files, log clearing,
registry key removal.

**Gotchas:**

- **Fires alongside 4663** (with DELETE access mask) — the pair tells you what
  was deleted and by whom.
- **SACL required** — no SACL = no event.

**Prerequisites:** Advanced Audit → "Object Access" → Success + SACLs

**MDE equivalent:** `DeviceFileEvents` (`ActionType == "FileDeleted"`) — MDE is
broader (no SACL needed).

-----

### Event ID 4662 — An operation was performed on an object

**Captures:** generic directory service access — used for AD objects on DCs.

**Key fields:** `SubjectUserName`, `ObjectServer`, `ObjectType`, `ObjectName`,
`OperationType`, `AccessMask`, `Properties`

**Detection use:**

- **DCSync detection:** correlate with `OperationType` containing specific
  replication GUIDs (`{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` and
  `{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}`) targeting the DS-Replication-Get-Changes
  and DS-Replication-Get-Changes-All extended rights.
- AD object enumeration: high-volume 4662 from reconnaissance tooling.

**Gotchas:**

- **Extremely high volume on DCs** — almost every AD operation generates 4662.
  Needs aggressive filtering by `ObjectType`, `AccessMask`, or `Properties`.
- **DCSync detection requires specific GUID filtering** — generic 4662 alerting
  is infeasible.

**Prerequisites:** Advanced Audit → "DS Access → Audit Directory Service Access" → Success

**MDE equivalent:** `IdentityDirectoryEvents` (MDI required) provides cleaner
DCSync detection than raw 4662.

-----

## Account Management

### Event ID 4720 — A user account was created

**Captures:** local or domain user account creation.

**Key fields:**

- `SubjectUserName` — who created it
- `TargetUserName` — the new account name
- `TargetDomainName` — domain
- `TargetSid` — SID of the new account
- `SamAccountName` — the SAM account name

**Detection use:** rogue account creation — unexpected accounts created outside
change windows.

**MDE equivalent:** `DeviceEvents` (`ActionType == "UserAccountCreated"`).

**Prerequisites:** Advanced Audit → "Account Management → Audit User Account Management" → Success

-----

### Event ID 4726 — A user account was deleted

**Captures:** account deletion.

**Key fields:** Same structure as 4720.

**Detection use:** insider threat or cleanup activity — unexpected account deletion,
especially of service accounts or admin accounts.

**MDE equivalent:** `DeviceEvents` (`ActionType == "UserAccountDeleted"`).

**Prerequisites:** Same as 4720.

-----

### Event ID 4738 — A user account was changed

**Captures:** any modification to a user account — password change, group membership
change, UPN change, account flags (disabled, locked, etc.).

**Key fields:**

- `SubjectUserName` — who made the change
- `TargetUserName` — the modified account
- `PasswordLastSet` — timestamp
- `UserAccountControl` — flags indicating what changed (disabled, locked, etc.)

**Detection use:**

- Password changes on sensitive accounts
- Account enablement after disablement (reactivation)
- `UserAccountControl` flag changes indicating privilege escalation

**Gotchas:** 4738 is generic — the `UserAccountControl` field tells you what changed,
but parsing it requires knowledge of the bitmask values.

**MDE equivalent:** `DeviceEvents` (`ActionType == "UserAccountModified"`).

**Prerequisites:** Same as 4720.

-----

### Event IDs 4727 / 4731 / 4754 — A security-enabled global / local / universal group was created

**Captures:** security group creation.

**Detection use:** unexpected group creation — especially admin-equivalent groups.

**MDE equivalent:** `DeviceEvents` (`ActionType == "SecurityGroupCreated"`).

**Prerequisites:** Advanced Audit → "Account Management → Audit Security Group Management" → Success

-----

### Event IDs 4730 / 4734 / 4758 — A security-enabled global / local / universal group was deleted

**Captures:** security group deletion.

**Detection use:** group cleanup — could indicate anti-forensics or privilege
escalation (removing restrictions).

**MDE equivalent:** `DeviceEvents` (`ActionType == "SecurityGroupDeleted"`).

**Prerequisites:** Same as 4727.

-----

### Event ID 4732 — A member was added to a security-enabled local group

**Captures:** user added to a local group (e.g., Administrators, Backup Operators,
Remote Desktop Users).

**Key fields:**

- `SubjectUserName` — who added them
- `TargetUserName` — the group
- `MemberName` — the SID of the added member (may need resolution)

**Detection use:**

- **Privilege escalation:** added to `Administrators`, `Backup Operators`,
  `Remote Desktop Users`
- **Backdoor creation:** adding an unexpected account to a privileged group

**MDE equivalent:** `DeviceEvents` (`ActionType == "UserAccountAddedToLocalGroup"`).

**Prerequisites:** Advanced Audit → "Account Management → Audit Security Group Management" → Success

-----

### Event ID 4733 — A member was removed from a security-enabled local group

**Captures:** member removal from a local group.

**Detection use:** cleanup activity — pair with 4732 to detect "add-then-remove"
techniques (temporary privilege escalation).

**MDE equivalent:** `DeviceEvents` (`ActionType == "UserAccountRemovedFromLocalGroup"`).

**Prerequisites:** Same as 4732.

-----

## System Security & Policy

### Event ID 4697 — A service was installed in the system

**Captures:** Windows service installation (new service creation).

**Key fields:**

- `SubjectUserName` — who installed it
- `ServiceName` — the service name
- `ImagePath` — the executable path (high-value — reveals payload location)
- `ServiceType` — `0x1` (kernel driver), `0x10` (own process), `0x20` (share process)
- `StartType` — `0x2` (auto start), `0x3` (demand start), `0x4` (disabled)
- `AccountName` — the account the service runs as (e.g., `LocalSystem`)

**Detection use:**

- **Service-based persistence:** `ImagePath` pointing to unusual locations
  (`C:\Users\`, `C:\Temp\`, `C:\Windows\Temp\`)
- **Kernel rootkits:** `ServiceType == 0x1` (kernel driver) from unexpected sources
- **Privilege escalation:** service running as `LocalSystem` with `ImagePath` in
  user-writable directory (unquoted path vulnerability)

**Gotchas:**

- **Legitimate software installs generate 4697** — baseline by `ImagePath` location
  and `ServiceName` patterns.
- **Event 7045 in System log captures the same thing** — some SIEMs ingest 7045
  more reliably than 4697.

**Prerequisites:** Advanced Audit → "Audit Security System Extension" → Success

**MDE equivalent:** `DeviceEvents` (`ActionType == "ServiceInstalled"`).

**Sentinel (System log 7045 — often more reliable):**
```kql
WindowsEvent
| where EventID == 7045 and Channel == "System"
```

-----

### Event ID 4698 — A scheduled task was created

**Captures:** new scheduled task creation.

**Key fields:**

- `SubjectUserName`
- `TaskName` — task name
- `TaskContent` — **the full XML of the task definition** — extremely valuable for
  forensics (contains command line, triggers, actions, principals)

**Detection use:**

- **Persistence:** tasks executing from unusual paths, hidden tasks
  (`TaskName` starting with `\` or GUID-named)
- **Lateral movement:** remote task creation via `atsvc` or `ITaskScheduler`
- **Command inspection:** `TaskContent` XML reveals the full payload

**Gotchas:**

- **`TaskContent` is large and XML-encoded** — needs parsing in SIEM queries.
- **Legitimate software creates many scheduled tasks** — baseline heavily.
- **Event 106 in TaskScheduler/Operational** also captures this with cleaner formatting.

**MDE equivalent:** `DeviceEvents` (`ActionType == "ScheduledTaskCreated"`).

**Prerequisites:** Advanced Audit → "Audit Other Object Access Events" → Success

-----

### Event ID 4699 — A scheduled task was deleted

**Captures:** scheduled task deletion.

**Detection use:** cleanup — adversaries deleting their persistence tasks after use.

**MDE equivalent:** `DeviceEvents` (`ActionType == "ScheduledTaskDeleted"`).

**Prerequisites:** Same as 4698.

-----

### Event ID 4702 — A scheduled task was updated

**Captures:** scheduled task modification.

**Detection use:** task hijacking — modifying an existing legitimate task to run
malicious code instead.

**MDE equivalent:** `DeviceEvents` (`ActionType == "ScheduledTaskUpdated"`).

**Prerequisites:** Same as 4698.

-----

### Event ID 4719 — System audit policy was changed

**Captures:** audit policy modification — someone changed what's being logged.

**Key fields:**

- `SubjectUserName` — who changed it
- `CategoryId` — which audit category was modified
- `SubcategoryId` — which subcategory
- `SubcategoryGuid` — GUID of the subcategory
- `AuditPolicyChanges` — what changed (added/removed success/failure)

**Detection use:**

- **Anti-forensics:** attackers disabling auditing to hide their tracks
- **Policy drift:** unauthorized audit policy changes

**Gotchas:**

- **Legitimate GPO updates generate 4719** — correlate with change management.
- **The SubcategoryId needs translation** to human-readable subcategory names.

**Prerequisites:** Advanced Audit → "Audit Policy Change → Audit Audit Policy Change" → Success

**MDE equivalent:** `DeviceEvents` (`ActionType == "AuditPolicyModification"`).

-----

### Event ID 4907 — Auditing settings on object were changed

**Captures:** SACL modification — someone changed the audit settings on a file,
folder, or registry key.

**Detection use:** anti-forensics — removing SACLs from sensitive objects to
prevent future audit events from firing.

**MDE equivalent:** none direct.

**Prerequisites:** Advanced Audit → "Audit Policy Change → Audit Authorization Policy Change" → Success

-----

## Kerberos & NTLM (on Domain Controllers)

### Event ID 4768 — A Kerberos authentication ticket (TGT) was requested

**Captures:** every Kerberos TGT request (AS-REQ) on a DC.

**Key fields:**

- `TargetUserName` — the account requesting the TGT
- `TargetDomainName` — domain
- `IpAddress` — source IP
- `TicketOptions` — flags
- `Status` — `0x0` = success; `0x12` = pre-auth required; `0x18` = pre-auth failed

**Detection use:**

- **AS-REP Roasting:** TGT request with `TicketOptions` containing `0x40810010`
  (no pre-auth) for accounts that don't require pre-auth
- **Brute-force:** repeated 4768 failures (`Status != 0x0`) from single source
- **Unusual sources:** service accounts requesting TGTs from workstations

**Prerequisites:** Advanced Audit → "Account Logon → Audit Kerberos Authentication Service" → Success

**MDE equivalent:** `IdentityLogonEvents` (MDI required) — though MDE identity tables
provide cleaner TGT-focused signal than raw 4768.

-----

### Event ID 4769 — A Kerberos service ticket was requested

**Captures:** every TGS-REQ (service ticket request) on a DC.

**Key fields:**

- `TargetUserName` — the account
- `ServiceName` — the SPN being requested (`HTTP/webserver`, `MSSQLSvc/dbserver`, etc.)
- `TicketOptions`
- `TicketEncryptionType` — `0x1` = DES; `0x3` = DES-CBC-MD5; `0x11` = AES128-CTS-HMAC-SHA1-96;
  `0x12` = AES256-CTS-HMAC-SHA1-96; `0x17` = RC4-HMAC (**Kerberoasting signal**)

**Detection use:**

- **Kerberoasting:** `TicketEncryptionType == 0x17` (RC4) from unexpected accounts,
  especially for high-value SPNs
- **SPN enumeration:** systematic 4769 requests for many different SPNs

**Gotchas:**

- **RC4 is still common for legacy services** — not every 0x17 is Kerberoasting.
  Filter by source account and SPN rarity.
- **Extremely high volume** — every service access generates a 4769.

**Prerequisites:** Advanced Audit → "Account Logon → Audit Kerberos Service Ticket Operations" → Success

**MDE equivalent:** `IdentityLogonEvents` (MDI required).

-----

### Event ID 4771 — Kerberos pre-authentication failed

**Captures:** Kerberos pre-authentication failure on a DC.

**Key fields:**

- `TargetUserName` — the account
- `IpAddress` — source
- `Status` — `0x18` = bad password; `0x12` = account locked; `0x17` = password expired
- `PreAuthType` — encryption type used

**Detection use:**

- **Password spray against Kerberos:** repeated 4771 with different usernames
  from single IP
- **AS-REP Roasting precursor:** 4771 for accounts with pre-auth disabled
- **Account enumeration:** systematic 4771 across username space

**Prerequisites:** Advanced Audit → "Account Logon → Audit Kerberos Authentication Service" → Failure

**MDE equivalent:** `IdentityLogonEvents` (MDI required).

-----

### Event ID 4776 — The computer attempted to validate the credentials for an account

**Captures:** NTLM credential validation (authentication via NTLM, not Kerberos).

**Key fields:**

- `TargetUserName` — the account being validated
- `Workstation` — source workstation name
- `Status` — `0x0` = success; `0xC0000064` = no such user; `0xC000006A` = bad password

**Detection use:**

- **NTLM relay detection:** 4776 from unexpected workstations for privileged accounts
- **Pass-the-hash:** 4776 with `Status == 0x0` but unusual `Workstation` value
- **Password spray via NTLM:** repeated 4776 failures

**Gotchas:**

- **Workstation field is the submitting system name** — not always the actual
  source IP (may differ behind NAT/proxies).
- **Many legacy protocols still use NTLM** — baseline by `TargetUserName` and
  `Workstation` before alerting.

**Prerequisites:** Advanced Audit → "Account Logon → Audit Credential Validation" → Success/Failure

**MDE equivalent:** `IdentityLogonEvents` (MDI required).

-----

## Active Directory (on Domain Controllers)

### Event ID 5136 — A directory service object was modified

**Captures:** attribute-level changes to AD objects (users, groups, OUs, computers).

**Key fields:**

- `SubjectUserName` — who made the change
- `ObjectDN` — distinguished name of the modified object
- `AttributeLDAPDisplayName` — which attribute changed (e.g., `member`, `userAccountControl`)
- `AttributeValue` — the new value
- `OperationType` — `%%14674` (value added), `%%14675` (value deleted)

**Detection use:**

- **Privilege escalation:** `member` attribute changes on `Domain Admins`,
  `Enterprise Admins`, `Schema Admins`, `Account Operators`
- **DCSync ACL modification:** `nTSecurityDescriptor` changes adding
  `DS-Replication-Get-Changes` rights
- **Sensitive attribute changes:** `userAccountControl`, `unicodePwd`, `servicePrincipalName`

**Gotchas:**

- **Extremely high volume on busy DCs** — attribute changes happen constantly.
  Filter by `ObjectDN` (target privileged groups) or `AttributeLDAPDisplayName`.
- **The `member` attribute of large groups changes frequently** — don't alert on
  every 5136 for `Domain Users`.

**Prerequisites:** Advanced Audit → "DS Access → Audit Directory Service Changes" → Success

**MDE equivalent:** `IdentityDirectoryEvents` (MDI required) provides cleaner
AD change signal than raw 5136.

-----

### Event ID 5137 — A directory service object was created

**Captures:** new AD object creation (users, groups, OUs, GPOs, computers).

**Key fields:** `SubjectUserName`, `ObjectDN`, `ObjectClass` (`user`, `group`, `organizationalUnit`)

**Detection use:** rogue AD object creation — unexpected accounts, backdoor groups,
or GPOs created outside change windows.

**MDE equivalent:** `IdentityDirectoryEvents` (MDI required).

**Prerequisites:** Same as 5136.

-----

### Event ID 5139 — A directory service object was moved

**Captures:** AD object relocation to a different OU.

**Detection use:** unusual — OUs define policy scope. Moving objects between OUs
can be a policy-escalation technique.

**MDE equivalent:** `IdentityDirectoryEvents` (MDI required).

**Prerequisites:** Same as 5136.

-----

### Event ID 5141 — A directory service object was deleted

**Captures:** AD object deletion.

**Detection use:** cleanup — adversaries deleting accounts, groups, or GPOs after use.
Note: AD Recycle Bin may allow recovery.

**MDE equivalent:** `IdentityDirectoryEvents` (MDI required).

**Prerequisites:** Same as 5136.

-----

## Network Sharing & Firewall

### Event ID 5140 — A network share object was accessed

**Captures:** network share access (SMB).

**Key fields:**

- `SubjectUserName` — who accessed it
- `ShareName` — `\\*\IPC$`, `\\*\ADMIN$`, `\\*\C$`, `\\*\SYSVOL`
- `ShareLocalPath` — local path on the server
- `IpAddress` — source IP
- `AccessMask` — permissions requested

**Detection use:**

- **Lateral movement:** `ADMIN$`, `C$`, `IPC$` access from unexpected workstations
- **PsExec usage:** `IPC$` + `ADMIN$` + `PSEXESVC.exe` service install (correlate
  with 4697/7045)
- **Data staging:** large-volume access to file shares from atypical accounts

**Gotchas:**

- **5140 is very high volume** — every file share access generates it. Filter by
  `ShareName` (focus on `ADMIN$`, `C$`, `IPC$`) and source IP.
- **5145 provides per-file granularity** — use 5145 for sensitive-file-access
  detection, not 5140.

**Prerequisites:** Advanced Audit → "Object Access → Audit File Share" → Success

**MDE equivalent:** `DeviceEvents` (`ActionType == "SmbSessionOpened"`).

-----

### Event ID 5145 — A network share object was checked to see whether client can be granted desired access

**Captures:** detailed per-file share access — fires when the system checks
permissions for a specific file over SMB.

**Key fields:**

- `SubjectUserName`
- `ShareName` — the share
- `RelativeTargetName` — the specific file path within the share
- `AccessMask` — requested permissions
- `IpAddress` — source

**Detection use:**

- **Sensitive file access over SMB:** per-file visibility into what's being
  accessed on file servers
- **Lateral movement + file access:** combining `ShareName` == `ADMIN$` with
  `RelativeTargetName` revealing payload staging

**Gotchas:**

- **Higher volume than 5140** — every file open check generates 5145.
- **Requires "Audit Detailed File Share"** — different subcategory from 5140.

**Prerequisites:** Advanced Audit → "Object Access → Audit Detailed File Share" → Success

**MDE equivalent:** none at per-file granularity.

-----

### Event ID 5156 — The Windows Filtering Platform has allowed a connection

**Captures:** WFP-allowed network connection.

**Key fields:**

- `SourceAddress`, `SourcePort`
- `DestAddress`, `DestPort`
- `Protocol` — 6 (TCP), 17 (UDP), 1 (ICMP)
- `Application` — process path that initiated
- `Direction` — `%%14592` (inbound), `%%14593` (outbound)
- `FilterRunTimeID` — which WFP filter allowed it

**Detection use:**

- WFP-based network telemetry when other sources (Sysmon, MDE) aren't available
- Baseline outbound connections from sensitive processes

**Gotchas:**

- **Enormous volume** — every allowed connection generates this. Most environments
  do NOT enable 5156 due to ingest cost.
- **MDE and Sysmon provide cleaner network signal** — prefer those. Enable 5156
  only as a fallback.

**Prerequisites:** Advanced Audit → "Object Access → Audit Filtering Platform Connection" → Success

**MDE equivalent:** `DeviceNetworkEvents` (`ConnectionSuccess`).

-----

### Event ID 5157 — The Windows Filtering Platform has blocked a connection

**Captures:** WFP-blocked connection.

**Detection use:** blocked outbound C2 attempts, lateral movement blocked by firewall.

**Gotchas:**

- **Blocked connections are high-fidelity** — far fewer than allowed connections.
- **Windows Firewall default blocks can generate noise** — baseline by `Application`
  and `DestPort`.

**Prerequisites:** Advanced Audit → "Object Access → Audit Filtering Platform Connection" → Failure

**MDE equivalent:** `DeviceNetworkEvents` (`ConnectionFailed`).

-----

### Event ID 5158 — The Windows Filtering Platform has permitted a bind to a local port

**Captures:** port binding (listen) event.

**Detection use:** unexpected listening services — new ports opened on sensitive systems.

**Prerequisites:** Advanced Audit → "Object Access → Audit Filtering Platform Connection" → Success

**MDE equivalent:** `DeviceNetworkEvents` (`ListeningConnectionCreated`).

-----

## Security-Only Signals (no MDE equivalent)

These Security channel events have no clean Defender ActionType equivalent —
they require the Security log to be ingested:

| Event ID | Description | Why MDE doesn't cover it |
|---|---|---|
| 4648 | Explicit credential logon (`runas`) | MDE sees process creation, not credential handoff |
| 4672 | Admin-equivalent logon privileges | No privilege-level granularity in DeviceLogonEvents |
| 4689 | Process termination | Gap in MDE — no termination ActionType |
| 4657 | Registry value set (with OldValue) | MDE captures new value only; OldValue is Security-only |
| 4719 | Audit policy change | Defender manages its own audit policy; doesn't log Windows audit changes |
| 4907 | SACL change | Security-channel only |
| 5156-5158 | WFP allowed/blocked connections | MDE has DeviceNetworkEvents; WFP is fallback only |

-----

## Cross-source comparison

| Detection Scenario | Security Channel | Sysmon | MDE |
|---|---|---|---|
| Process creation | 4688 (+ command line if enabled) | Event 1 | DeviceProcessEvents |
| Process termination | 4689 | Event 5 | Not logged |
| File create | 4663 (requires SACL) | Event 11 | DeviceFileEvents |
| File modify content | Not directly logged | Event 2 (timestamps only) | DeviceFileEvents |
| Registry value set | 4657 (with OldValue!) | Event 13 | DeviceRegistryEvents |
| Network connection | 5156 (volume prohibitive) | Event 3 | DeviceNetworkEvents |
| Logon | 4624/4625 | Not logged | DeviceLogonEvents |
| Service install | 4697 | Not logged | DeviceEvents |
| Scheduled task | 4698 (TaskContent XML) | Not logged | DeviceEvents |
| Account created | 4720 | Not logged | DeviceEvents |
| Admin logon | 4672 | Not logged | Not logged |
| LSASS access | Not directly logged | Event 10 | DeviceEvents |

**Rule of thumb:**
- Use **MDE** as the primary source — it's always-on, normalised, and has the
  best process ancestry
- Use **Sysmon** for process termination (Event 5), clipboard (24), raw disk (9),
  and Sysmon-as-prevention (27-29)
- Use **Security channel** for audit policy changes (4719), admin-equivalent
  logons (4672), explicit credential usage (4648), registry OldValue (4657),
  and process termination (4689)

-----

## Prerequisites summary table

| Subcategory | Events | Common Prerequisites |
|---|---|---|
| Logon | 4624, 4625 | Enable Success + Failure |
| Logoff | 4634, 4647 | Enable Success |
| Account Lockout | 4740 | Enable Success + Failure |
| Other Logon/Logoff | 4648, 4778, 4779 | Enable Success |
| Special Logon | 4672 | Enable Success |
| Process Creation | 4688 | Enable Success + "Include command line" GPO |
| Process Termination | 4689 | Enable Success |
| File System | 4663, 4656, 4660 | Enable Success + **SACLs on targets** |
| Registry | 4657, 4656 | Enable Success + **SACLs on targets** |
| Audit Policy Change | 4719, 4907 | Enable Success + Failure |
| Security Group Mgmt | 4727-4734, 4754, 4758 | Enable Success |
| User Account Mgmt | 4720, 4726, 4738 | Enable Success |
| Security System Extension | 4697 | Enable Success |
| Other Object Access | 4698-4702 | Enable Success |
| DS Access | 5136-5141, 4662 | Enable Success (DC only) |
| File Share | 5140 | Enable Success |
| Detailed File Share | 5145 | Enable Success |
| Filtering Platform Connection | 5156-5158 | Enable Success + Failure |
| Kerberos Auth Service | 4768, 4771 | Enable Success + Failure (DC only) |
| Kerberos Service Ticket | 4769 | Enable Success + Failure (DC only) |
| Credential Validation | 4776 | Enable Success + Failure (DC only) |

-----

*Last reviewed: 2026-05-28. Event descriptions based on Windows Server 2019/2022
schema. Older Windows versions may lack some events or fields.*
