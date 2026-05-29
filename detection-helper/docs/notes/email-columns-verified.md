---
date: "2026-05-28"
source:
  - "docs/advanced-hunting/advanced-hunting-emailevents-table.md"
  - "docs/tenant/actiontypes/EmailEvents.md"
scope: "MDO EmailEvents — all tenants with MDO"
confidence: confirmed
---

# Email Events — Verified Column Reference

**Q:** Which columns are reliable for email threat hunting in MDE?

**A:** `EmailEvents` — confirmed columns for threat hunting:

**Identity / routing:** `Timestamp`, `NetworkMessageId`, `InternetMessageId`,
`RecipientEmailAddress`, `SenderFromAddress`, `SenderDisplayName`, `Subject`

**Threat metadata:** `ThreatTypes`, `ThreatNames`, `DetectionMethods`, `ConfidenceLevel`

**Delivery / action:** `EmailAction`, `DeliveryLocation`, `EmailDirection`

**Auth:** `AuthDetails` (contains SPF/DKIM/DMARC results)

**Common traps:**
- `SenderMailFromAddress` does NOT exist — use `SenderFromAddress`
- `AttachmentCount` and `UrlCount` exist but verify they're populated for your tenant
- On-prem Exchange email NOT covered — only Exchange Online with MDO

**Prerequisites:** Microsoft Defender for Office 365 (MDO) license

**Verification query:**
```kql
EmailEvents
| where Timestamp > ago(7d)
| summarize count(), dcount(RecipientEmailAddress),
    make_set(ThreatTypes), make_set(DetectionMethods)
```
