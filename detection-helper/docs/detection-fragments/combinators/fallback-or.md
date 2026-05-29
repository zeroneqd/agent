# Combinator: Fallback-OR

> Try Primitive A first (earlier in kill chain). If A is blind (🔴 gap),
> fall back to Primitive B (later but more reliable).
> Documents the gap explicitly rather than silently missing it.

## Template

```markdown
## Primary detection (earlier in kill chain)

Target: {{primitive_A}} [{{confidence_A}}]
```kql
{{detection_block_A}}
```

**Blind spots:** {{gaps_A}}

---

## Fallback detection (if primary is blind)

Target: {{primitive_B}} [{{confidence_B}}]
Rationale: {{why_B_is_available_when_A_is_not}}
```kql
{{detection_block_B}}
```

**Gap mitigation for A:** {{how_to_close_gap_A}}
```

## Example: Process injection (P2) blind → fallback to process spawn (P1)

```markdown
## Primary: Code Injection (P2) [L4]

Catches in-memory fileless malware. May be blind to kernel injection.
```kql
// See p2-code-injection.md
```

**Blind spots:** Kernel-level injection invisible; some EDR self-injection.

---

## Fallback: Process Spawn (P1) [L4]

If injection succeeded, malware usually spawns a process. Later but reliable.
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ActionType == "ProcessCreated"
| where InitiatingProcessFileName in (VulnerableApps)
| where FileName in (SuspiciousChildren)
```

**Gap mitigation for P2:** Deploy Sysmon Events 8/10 for additional injection
visibility. Enable "Audit Kernel Object" for kernel-level activity.
```

## Common fallback pairs

| Primary (early) | Fallback (later) | When primary is blind |
|---|---|---|
| P2: Code Injection | P1: Process Spawn | Kernel injection, hollowed process |
| P8: DNS Query | P7: Outbound Connection | DoH bypass, cached DNS |
| P3: File Drop | P1: Process Spawn | Short-lived files, direct execution |
| P5: Registry Persistence | P10: Task/Service | WMI persistence instead of registry |
| P11: LSASS Access | P3: File Drop (dump file) | Credential Guard blocks LSASS |

## When to use

- Primary primitive has known gaps
- Primary is high-fidelity when visible but unreliable
- You want to document the gap rather than ignore it
