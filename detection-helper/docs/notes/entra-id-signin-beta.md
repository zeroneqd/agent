---
date: "2026-05-28"
source:
  - "docs/advanced-hunting/advanced-hunting-aadsignineventsbeta-table.md"
  - "docs/schema-overview.md"
scope: "Entra ID sign-ins — beta table"
confidence: confirmed
---

# Entra ID Sign-in Events — Beta Table Awareness

**Q:** What's the state of Entra ID sign-in logging in Defender XDR?

**A:** Two tables with different purposes and maturity levels:

**`AADSignInEventsBeta`** — Entra ID native sign-ins
- Interactive and non-interactive user sign-ins
- MFA results, Conditional Access results, risk state
- **Beta table — schema may change without notice**
- Service principal sign-ins NOT here (use `AADSpnSignInEventsBeta`)
- Requires Entra ID connector to Defender XDR or Sentinel

**`IdentityLogonEvents`** — MDI-sourced (on-prem AD / hybrid)
- Kerberos, NTLM on monitored DCs
- Requires MDI sensor on DCs
- Different data source, different coverage

**Critical distinction:**
- Pure Entra ID (cloud-only) questions → `AADSignInEventsBeta`
- On-prem AD / hybrid questions → `IdentityLogonEvents`
- Kerberos/NTLM specifically → `IdentityLogonEvents` (MDI)

**Key columns (AADSignInEventsBeta):** `AccountUpn`, `AccountObjectId`,
`IPAddress`, `Location`, `ConditionalAccessStatus`, `AuthenticationRequirement`,
`RiskState`, `RiskLevelDuringSignIn`, `MfaDetail`, `Status`, `ErrorCode`

**Verification query:**
```kql
union AADSignInEventsBeta, IdentityLogonEvents
| where Timestamp > ago(7d)
| summarize count() by Table=source_table
```
