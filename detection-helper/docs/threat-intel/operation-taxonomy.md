# Exploit Operation Taxonomy

> **Purpose.** Maps exploit primitives (things malware does to the OS) to telemetry
> tables, ActionTypes, and detection patterns. This is the translation layer between
> threat intelligence and detection engineering.
>
> **How to use:** When decomposing a CVE or threat report, identify which primitives
> are involved, then look up the corresponding telemetry and detection guidance here.

## Taxonomy structure

Each entry follows this format:

```
### Primitive name

**Description:** What happens at the OS level.
**Typical triggers:** CVE classes / malware families that use this.
**Telemetry mapping:**
  - Primary table: `TableName` — ActionType(s)
  - Secondary table: `TableName` — correlating signal
  - Windows event alternative: Event ID(s)
**Detection patterns:** `detection-patterns/<category>/<pattern>.md`
**Blind spots:** Known gaps where this primitive may be invisible.
**Sequence context:** Where this typically appears in a kill chain.
```

-----

## Process Execution Primitives

### P1: Process Spawn from Exploited Parent

**Description:** The exploited application (browser, Office, PDF reader, Java,
 etc.) launches a child process — typically a shell, script interpreter, or
 LOLBin.

**Typical triggers:**
- Office macros (CVE-2017-11882, CVE-2021-40444)
- Browser exploits (CVE-2021-21220, CVE-2023-XXXX)
- PDF exploits (CVE-2023-XXXX)
- Java deserialization (CVE-2021-44228 Log4Shell)
- RCE in any application that then spawns a process

**Telemetry mapping:**
- **Primary:** `DeviceProcessEvents` — `ActionType == "ProcessCreated"`
- **Key columns:** `FileName` (child), `InitiatingProcessFileName` (parent),
  `InitiatingProcessParentFileName` (grandparent), `ProcessCommandLine`
- **Correlation:** `DeviceImageLoadEvents` — unsigned DLL loaded into parent
  just before spawn
- **Windows:** Security 4688 — `NewProcessName`, `ParentProcessName`

**Detection approach:**
1. Known-vulnerable parent + unexpected child:
   ```kql
   let VulnerableParents = dynamic([
       "winword.exe", "excel.exe", "powerpnt.exe",     // Office
       "acrord32.exe", "acrobat.exe",                    // Adobe
       "chrome.exe", "msedge.exe", "firefox.exe",        // Browsers
       "java.exe", "javaw.exe",                          // Java
       "wscript.exe", "cscript.exe"                      // Scripts
   ]);
   let SuspiciousChildren = dynamic([
       "cmd.exe", "powershell.exe", "pwsh.exe",
       "wscript.exe", "cscript.exe", "mshta.exe",
       "regsvr32.exe", "rundll32.exe", "certutil.exe"
   ]);
   DeviceProcessEvents
   | where Timestamp > ago(24h)
   | where InitiatingProcessFileName in (VulnerableParents)
   | where FileName in (SuspiciousChildren)
   ```
2. Office app + network child (browser, curl, certutil)
3. Java + ANY child process (java rarely spawns shells legitimately)

**Blind spots:**
- If parent process name is generic (e.g., `services.exe`, `svchost.exe`),
  attribution to the vulnerable app is lost — need correlation with process
  tree or command-line arguments
- Process hollowing (P3) may skip the spawn event — parent creates child
  normally then overwrites its memory

**Sequence context:** Typically follows P2 (Code Injection) or immediately
after exploitation. May skip to P4 (File Drop) if payload is file-based.

**Detection patterns:**
- `detection-patterns/execution/lolbin-abuse.md` — for LOLBin children
- `detection-patterns/defense-evasion/process-injection.md` — if hollowed

-----

### P2: Code Injection into Running Process

**Description:** The exploit writes shellcode or a DLL into the memory space of
an existing process, then executes it. Common techniques: DLL injection,
process hollowing, APC injection, thread hijacking.

**Typical triggers:**
- Browser exploit → inject into legitimate Windows process
- Office macro → inject into explorer.exe or svchost.exe
- Java exploit → reflectively load class
- Post-exploitation frameworks (Cobalt Strike, Metasploit) — standard behavior

**Telemetry mapping:**
- **Primary:** `DeviceEvents` — memory ActionTypes
  - `WriteProcessMemoryApiCall`
  - `CreateRemoteThreadApiCall`
  - `NtAllocateVirtualMemoryRemoteApiCall`
  - `NtMapViewOfSectionRemoteApiCall`
  - `NtProtectVirtualMemoryRemoteApiCall`
  - `MemoryRemoteProtect`
- **Secondary:** `DeviceImageLoadEvents` — `ImageLoaded` with suspicious signer
- **Windows:** Sysmon 8 (CreateRemoteThread), Sysmon 10 (ProcessAccess)

**Detection approach:** See `detection-patterns/defense-evasion/process-injection.md`
for complete rules. Key approach: sequence detection (multiple memory APIs from
same source within minutes) or single suspicious API call from non-system process.

**Blind spots:**
- Early-boot injection (before MDE sensor initializes)
- Kernel-level injection (EDR bypass techniques)
- Some EDR agents themselves inject — exclusion list required
- Process Doppelgänging / Ghosting may not trigger all memory APIs

**Sequence context:** Usually follows exploitation (P0), precedes P1 (spawn) or
P4 (file drop). Some malware injects then stays in-memory (no further primitives).

**Detection patterns:** `detection-patterns/defense-evasion/process-injection.md`

-----

## File System Primitives

### P3: Payload File Drop

**Description:** The exploit or malware writes a file to disk — the payload,
a persistence mechanism, a tool, or extracted data.

**Typical triggers:**
- Exploit drops secondary stage (DLL, EXE, script)
- Macro extracts embedded payload to temp
- Post-exploitation tool download (certutil, bitsadmin)
- Credential dump written to disk (procdump, lsass.dmp)

**Telemetry mapping:**
- **Primary:** `DeviceFileEvents` — `ActionType == "FileCreated"`
- **Key columns:** `FileName`, `FolderPath`, `SHA1`, `SHA256`, `InitiatingProcessFileName`
- **Secondary:** `DeviceFileCertificateInfo` — signer info for dropped file
- **Windows:** Sysmon 11 (FileCreate), Security 4663 (with SACL)

**Detection approach:**
1. File create in user-writable path by exploited parent:
   ```kql
   let ExploitableApps = dynamic([
       "winword.exe", "excel.exe", "powerpnt.exe",
       "acrord32.exe", "chrome.exe", "msedge.exe", "java.exe"
   ]);
   let SuspiciousPaths = dynamic([
       @"C:\Users\", @"C:\Temp\", @"C:\Windows\Temp\",
       @"\AppData\Local\Temp\", @"\AppData\Roaming\"
   ]);
   let ExecutableExts = dynamic([".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".hta"]);
   DeviceFileEvents
   | where Timestamp > ago(24h)
   | where ActionType == "FileCreated"
   | where InitiatingProcessFileName in (ExploitableApps)
   | where FolderPath has_any SuspiciousPaths
   | where FileName has_any ExecutableExts
   | project Timestamp, DeviceName, FileName, FolderPath,
             SHA1, Parent=InitiatingProcessFileName,
             ParentCmd=InitiatingProcessCommandLine
   ```
2. Unsigned executable created by Office/browser
3. Double-extension files (`.pdf.exe`, `.docx.js`)

**Blind spots:**
- File drops to paths excluded by MDE sensor config
- Very short-lived files (create → execute → delete within sensor poll window)
- ADS (Alternate Data Streams) — partial visibility in MDE

**Sequence context:** Can appear at any stage — initial payload delivery,
staging, persistence setup, or data staging before exfiltration.

-----

### P4: File Modification (Config Tampering)

**Description:** Modifying existing system files or configuration — disabling
security tools, modifying hosts file, changing boot config.

**Typical triggers:**
- Malware adds Windows Defender exclusion
- Modifies hosts file to redirect AV update servers
- Changes firewall rules
- Disables security services via config files

**Telemetry mapping:**
- **Primary:** `DeviceFileEvents` — `ActionType == "FileModified"`
- **Key targets:**
  - `C:\Windows\System32\drivers\etc\hosts`
  - Registry via `DeviceRegistryEvents` (more reliable than file-mod for config)
- **Windows:** Security 4663 (with SACL — rarely configured for system files)

**Blind spots:**
- `FileModified` on Linux is sparse (fanotify limitations)
- Many config changes go through registry, not files
- Direct kernel disk I/O may bypass file system hooks

**Sequence context:** Usually post-initial-access, during defense evasion or
persistence establishment.

-----

## Registry Primitives

### P5: Registry Persistence

**Description:** Writing to registry Run keys, Winlogon, services, or other
persistence locations.

**Typical triggers:**
- Nearly all malware families establish persistence
- Exploit kits write Run keys
- Post-exploitation frameworks (Empire, Cobalt Strike) add persistence

**Telemetry mapping:**
- **Primary:** `DeviceRegistryEvents` — `ActionType == "RegistryValueSet"`
- **Key paths:**
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
  - `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\SYSTEM\CurrentControlSet\Services`
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Startup`
- **Key columns:** `RegistryKey`, `RegistryValueName`, `RegistryValueData`,
  `InitiatingProcessFileName`
- **Windows:** Sysmon 13 (RegistryEvent ValueSet), Security 4657 (with SACL)

**Detection approach:**
1. Any Run key modification by non-system process
2. Registry value data contains a path to user-writable directory
3. Registry modification correlating with suspicious file create (P3)

**Blind spots:**
- Windows ONLY — no registry on Linux/macOS
- Some persistence mechanisms use WMI (see P9) or scheduled tasks (see P10)
  rather than registry
- Transacted registry operations may not surface until commit

**Sequence context:** Typically after initial execution (P1), before establishing
long-term access. May be delayed (sleep + then persist).

-----

### P6: Security Tool Disablement

**Description:** Registry modifications that disable Windows Defender, firewall,
EDR, or logging.

**Typical triggers:**
- Ransomware disabling Defender before encryption
- Post-exploitation frameworks disabling AMSI, ETW
- Attackers modifying audit policy via registry

**Telemetry mapping:**
- **Primary:** `DeviceRegistryEvents` — `RegistryValueSet`
- **Key paths:**
  - `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` — disable Defender
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` — disable UAC
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels` — disable logging
- **Secondary:** `DeviceEvents` — `ActionType == "TamperingAttempt"`
- **Windows:** Security 4719 (audit policy change)

**Detection patterns:** Alert on ANY modification to Defender/registry security
keys by non-system processes.

**Sequence context:** Usually during defense evasion phase, after initial access
but before main payload execution.

-----

## Network Primitives

### P7: Outbound Connection (Beacon / C2 / Download)

**Description:** The compromised system connects outbound — downloading next
stage, beaconing to C2, or exfiltrating data.

**Typical triggers:**
- Exploit payload downloads second stage
- Malware establishes C2 channel
- Data exfiltration
- Lateral movement preparation (scanning, credential testing)

**Telemetry mapping:**
- **Primary:** `DeviceNetworkEvents` — `ConnectionSuccess`, `ConnectionAttempt`
- **Key columns:** `RemoteIP`, `RemotePort`, `RemoteUrl`, `InitiatingProcessFileName`
- **Secondary:** `DeviceNetworkEvents` — `DnsConnectionInspected` for DGA
- **Windows:** Sysmon 3 (NetworkConnect), Security 5156 (WFP — high volume)

**Detection approach:**
1. Exploited parent process + unexpected outbound connection:
   ```kql
   let ExploitableApps = dynamic([
       "winword.exe", "excel.exe", "powerpnt.exe",
       "acrord32.exe", "chrome.exe", "java.exe"
   ]);
   DeviceNetworkEvents
   | where Timestamp > ago(24h)
   | where ActionType == "ConnectionSuccess"
   | where InitiatingProcessFileName in (ExploitableApps)
   | where RemotePort in (80, 443, 8080, 4444, 5555)
   | where ipv4_is_private(RemoteIP) == false
   | summarize ConnectionCount=count(),
       URLs=make_set(RemoteUrl),
       Ports=make_set(RemotePort)
       by DeviceName, InitiatingProcessFileName, RemoteIP
   ```
2. DNS queries to known DGA patterns from non-browser processes
3. Connection to known-bad IPs (threat intel correlation)

**Blind spots:**
- DNS-over-HTTPS (DoH) — appears as HTTPS to provider IP, query invisible
- Hardcoded IP connections that bypass DNS
- Encrypted C2 over common ports (443) — content invisible without SSL inspection
- Short-lived connections may be sampled on high-volume systems

**Sequence context:** Usually after initial payload execution (P1), during C2
establishment. May also appear during exploitation (download stage).

-----

### P8: DNS Query (DGA / C2 Resolution)

**Description:** DNS lookups for C2 domains, DGAs, or payload delivery.

**Typical triggers:**
- Malware resolves C2 domain
- DGA-generated domains
- Staging server resolution

**Telemetry mapping:**
- **Primary:** `DeviceNetworkEvents` — `ActionType == "DnsConnectionInspected"`
- **Key columns:** `RemoteUrl` (domain), `InitiatingProcessFileName`
- **Secondary:** Sysmon 22 (DNSQuery) — more detailed, includes query name
  and results
- **Windows:** No native Security log DNS event (use Sysmon 22 or MDE)

**Blind spots:**
- DoH/DoT bypasses standard DNS visibility entirely
- Direct IP connections (no DNS lookup)
- Cached responses don't generate new query events

**Sequence context:** Usually just before P7 (outbound connection), or as
periodic beaconing without subsequent TCP connection (DNS-tunnel C2).

-----

## Persistence Primitives

### P9: WMI Event Subscription

**Description:** Creating permanent WMI event subscriptions for persistence —
the classic "WMI backdoor."

**Typical triggers:**
- Post-exploitation persistence
- APT tooling (WMImplant, etc.)
- Some ransomware families

**Telemetry mapping:**
- **Primary:** `DeviceEvents` — `ActionType == "WmiBindEventFilterToConsumer"`
- **Related:** `ProcessCreatedUsingWmiQuery`, `RemoteWmiOperation`
- **Windows:** Sysmon 19/20/21 (filter/consumer/binding)

**Detection approach:** Alert on ANY `WmiBindEventFilterToConsumer` — this fires
rarely in legitimate operation. Correlation: WMI binding + suspicious consumer
(e.g., `CommandLineEventConsumer`, `ActiveScriptEventConsumer`).

**Blind spots:**
- Windows ONLY
- Some legitimate IT automation uses WMI subscriptions — baseline first

**Sequence context:** Post-initial-access persistence. May be created days or
weeks after initial compromise.

**Detection patterns:** `detection-patterns/persistence/scheduled-task-abuse.md`
(WMI section)

-----

### P10: Scheduled Task / Service Creation

**Description:** Creating scheduled tasks or Windows services for persistence
or privilege escalation.

**Typical triggers:**
- Nearly all persistent malware
- Post-exploitation frameworks
- APT persistence mechanisms

**Telemetry mapping:**
- **Primary (task):** `DeviceEvents` — `ScheduledTaskCreated`, `ScheduledTaskUpdated`
- **Primary (service):** `DeviceEvents` — `ActionType == "ServiceInstalled"`
- **Key columns:** `AdditionalFields` (TaskContent XML for tasks), `FileName`,
  `InitiatingProcessFileName`
- **Windows:** Security 4698 (task created), 4697 (service installed), 7045 (System log)

**Detection approach:** See `detection-patterns/persistence/scheduled-task-abuse.md`
for complete rules. Key approaches: suspicious execution path, encoded commands,
non-system creator process.

**Sequence context:** Persistence phase. May appear immediately after initial
access or be delayed.

**Detection patterns:** `detection-patterns/persistence/scheduled-task-abuse.md`

-----

## Credential Primitives

### P11: LSASS Memory Access

**Description:** Attempting to read credential material from LSASS process memory.

**Typical triggers:**
- Post-exploitation credential dumping (Mimikatz, procdump, comsvcs.dll)
- Lateral movement preparation
- Ransomware that steals before encrypting

**Telemetry mapping:**
- **Primary:** `DeviceEvents` — `OpenProcessApiCall` targeting `lsass.exe`,
  `LocalSecurityAuthoritySubsystemServiceProcessAccessDenied`,
  `UntrustedExecutableLoadedByLsass`
- **Windows:** Sysmon 10 (ProcessAccess with TargetImage=lsass.exe)

**Detection approach:** See `detection-patterns/credential-access/lsass-access.md`
for complete rules. Key approach: sequence detection, correlation with known dumpers.

**Sequence context:** Credential access phase. Usually after initial access,
before lateral movement. May repeat periodically.

**Detection patterns:** `detection-patterns/credential-access/lsass-access.md`

-----

## Exploit-Specific Primitives

### P12: Vulnerable Application Exploitation Indicator

**Description:** Behavioral indicators that a specific application is being
exploited — not the exploit itself (which may be invisible), but the
post-exploitation footprint.

**Typical application-specific patterns:**

| Application | Exploitation Indicator | Telemetry |
|---|---|---|
| Office (Word/Excel) | Child process spawn (P1) | `DeviceProcessEvents` — parent is `winword.exe`/`excel.exe` |
| Office | Suspicious macro execution | `DeviceEvents` — `ActionType == "ScriptContent"` from Office |
| Adobe Acrobat | Child process from acrobat | `DeviceProcessEvents` — parent is `acrord32.exe` |
| Browser (Chrome/Edge) | Renderer process spawn | `DeviceProcessEvents` — multiple children from renderer |
| Java | Native code execution | `DeviceImageLoadEvents` — unsigned JNI DLL |
| IIS / SQL Server | w3wp.exe / sqlservr.exe child | `DeviceProcessEvents` — web/db parent + shell child |

**Key insight:** You rarely detect the exploit itself. You detect the
**post-exploitation behavior** it enables. Focus primitives P1-P11, not the
vulnerability trigger.

-----

## Kill chain sequencing

Typical order of primitives after successful exploitation:

```
Exploitation (often invisible)
    │
    ├──→ P2: Code Injection (optional — some malware skips to spawn)
    │
    ├──→ P1: Process Spawn from Exploited Parent ← HIGH SIGNAL
    │
    ├──→ P3: File Drop (payload staging)
    │
    ├──→ P7/P8: Network Connection / DNS (C2 establishment) ← HIGH SIGNAL
    │
    ├──→ P5/P9/P10: Persistence (registry, WMI, task, service)
    │
    ├──→ P6: Security Tool Disablement
    │
    ├──→ P11: Credential Access (LSASS)
    │
    └──→ P7 (again): Lateral Movement (SMB, RDP, WMI)
```

**Detection priority:** Primitives that are BOTH high-signal and early in the
chain provide the most value:
1. **P1** (Process Spawn) — reliable, high fidelity
2. **P7** (Network from exploited app) — reliable, catches C2 early
3. **P2** (Code Injection) — moderate noise, but catches fileless malware
4. **P10** (Task/Service creation) — reliable, but later in chain

**Gap-driven hunting:** If P1 is blind (e.g., process hollowing bypassed it),
fallback to P2 or P7. Document the gap and propose verification.

*Last updated: 2026-05-28*
