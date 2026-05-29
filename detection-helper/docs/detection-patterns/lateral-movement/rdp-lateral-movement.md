---
technique: T1021.001
technique_name: Remote Services: Remote Desktop Protocol
tactic: TA0008
data_sources: [DeviceLogonEvents, DeviceProcessEvents]
confidence: high
false_positive_rate: low
last_validated: 2026-05-28
---

# RDP Lateral Movement

Detects suspicious RDP connections that may indicate lateral movement:
unusual source IPs, non-admin accounts using RDP, RDP from non-standard
workstations, and suspicious processes spawned within RDP sessions.

## Detection logic

1. `DeviceLogonEvents` LogonType=10 with unusual source IPs or accounts
2. RDP sessions from external/public IPs
3. Process execution (`DeviceProcessEvents`) within RDP sessions
4. Account profiling: first-time RDP use by an account

## KQL — RDP from unusual source

```kql
// RDP logons (LogonType=10) from outside expected IP ranges
let InternalRanges = dynamic([
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "fc00::/7"  // IPv6 ULA
]);
let RDPAllowedAccounts = dynamic([
    "administrator", "domain\\rdp-admins"  // environment-specific
]);
DeviceLogonEvents
| where Timestamp > ago(24h)
| where ActionType == "LogonSuccess"
| where LogonType == 10  // RemoteInteractive (RDP)
| where isnotempty(RemoteIP)
| extend IsPrivate = ipv4_is_private(RemoteIP)
| where IsPrivate == false  // External/public IP
    or (AccountName !in (RDPAllowedAccounts)
        and IsPrivate == true)
| project Timestamp, DeviceName, AccountName, AccountDomain,
    RemoteIP, RemotePort, LogonType, FailureReason,
    InitiatingProcessFileName, ReportId
| order by Timestamp desc
```

## KQL — First-time RDP account detection

```kql
// Accounts using RDP for the first time in the lookback period
let HistoricalRDPUsers = materialize (
    DeviceLogonEvents
    | where Timestamp between (ago(90d)..ago(1d))
    | where ActionType == "LogonSuccess" and LogonType == 10
    | summarize HistoricalFirst=min(Timestamp) by AccountName, AccountSid
    | project AccountSid
);
DeviceLogonEvents
| where Timestamp > ago(24h)
| where ActionType == "LogonSuccess" and LogonType == 10
| join kind=leftanti (HistoricalRDPUsers) on AccountSid
| project Timestamp, DeviceName, AccountName, AccountDomain, AccountSid,
    RemoteIP, RemotePort
| order by Timestamp desc
```

## KQL — Process execution within RDP session

```kql
// Suspicious processes started within an RDP session
let SuspiciousInRDP = dynamic([
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "certutil.exe", "bitsadmin.exe", "net.exe", "net1.exe"
]);
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in (SuspiciousInRDP)
| where IsProcessRemoteSession == true
    or InitiatingProcessFileName =~ "rdpclip.exe"
    or InitiatingProcessFileName =~ "tstheme.exe"
    or ProcessRemoteSessionDeviceName != ""
| project Timestamp, DeviceName,
    FileName, ProcessCommandLine, ProcessIntegrityLevel,
    Parent=InitiatingProcessFileName, ParentCmd=InitiatingProcessCommandLine,
    AccountName, ProcessRemoteSessionDeviceName, ProcessRemoteSessionIP
| order by Timestamp desc
```

## KQL — RDP connection from non-domain-joined machine

```kql
// RDP logons where source device name is not recognized
DeviceLogonEvents
| where Timestamp > ago(24h)
| where ActionType == "LogonSuccess" and LogonType == 10
| where isempty(RemoteDeviceName)  // Can't resolve source hostname
    or RemoteDeviceName == "-"
| where ipv4_is_private(RemoteIP)  // Internal IP but no hostname = BYOD/non-domain
| project Timestamp, DeviceName, AccountName,
    RemoteIP, RemoteDeviceName, RemotePort
| order by Timestamp desc
```

## SPL

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4624 LogonType=10
| rex field=_raw "<Data Name=\"IpAddress\">(?<IpAddress>[^<]+)"
| rex field=_raw "<Data Name=\"TargetUserName\">(?<TargetUserName>[^<]+)"
| rex field=_raw "<Data Name=\"TargetDomainName\">(?<TargetDomainName>[^<]+)"
| where IpAddress!="-" AND IpAddress!="::1" AND IpAddress!="127.0.0.1"
| eval IsPrivate=if(cidrmatch("10.0.0.0/8", IpAddress)
    OR cidrmatch("172.16.0.0/12", IpAddress)
    OR cidrmatch("192.168.0.0/16", IpAddress), "private", "public")
| where IsPrivate="public"
| bin _time span=1h
| stats count as Connections by _time, ComputerName, TargetUserName, IpAddress
| where Connections > 5
```

## False positive guidance

**Expected noise sources:**
- Legitimate admin RDP from home offices (post-COVID, very common)
- MSP / vendor remote access
- Azure Bastion / jump host connections
- Helpdesk remote support tools

**Tuning:**
1. Maintain allowed-source IP ranges (office, VPN pools, jump hosts)
2. Exclude known service accounts that legitimately use RDP
3. Weight by account type — standard user RDP to server is more suspicious
   than admin RDP to workstation
4. Cross-reference with `DeviceProcessEvents` for post-logon activity

**Environment-specific exclusions:**
```kql
| where RemoteIP !in (
    "203.0.113.10",   // VPN pool
    "203.0.113.11",   // Jump host
    "198.51.100.50"   // MSP endpoint
)
```

## Performance notes

- `DeviceLogonEvents` with `LogonType==10` is moderate volume
- `ipv4_is_private()` is efficient — filter before string operations
- First-time detection requires 90-day historical scan — use materialize
- The process-within-RDP rule requires `IsProcessRemoteSession` which may
  not be populated on all sensor versions — check first

## Test validation

1. **Benign:** RDP from your known office IP — should NOT alert (exclusion list)
2. **Benign edge:** RDP from new home IP of known admin — may alert (new source)
3. **Malicious simulation:** RDP from a non-domain VM using a standard user account
   — should alert on all rules

## References

- `docs/advanced-hunting/advanced-hunting-devicelogonevents-table.md`
- `docs/windows-events/security-audit-events.md` (Events 4624, 4778, 4779)
