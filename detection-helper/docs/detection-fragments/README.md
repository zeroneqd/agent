# Detection Fragments

> **Purpose.** Composable detection building blocks. Primitives are single-behavior
> blocks. Combinators join them. Templates assemble the final output.
>
> **Philosophy:** Detect the behavior, not the tool. Primitives are technique-scoped.
> A fragment for "process spawn" catches all tools that spawn processes — not just
> the one mentioned in today's threat report.

## Structure

```
detection-fragments/
├── primitives/      ← Reusable single-behavior blocks (P1-P12)
│   ├── p1-process-spawn.md
│   ├── p2-code-injection.md
│   ├── p7-outbound-connection.md
│   └── p11-lsass-access.md
├── combinators/     ← How to combine primitives
│   ├── sequence-and.md     ← A THEN B within X minutes
│   ├── fallback-or.md      ← A, or if blind, B
│   └── early-chain.md      ← first primitive that fires
└── templates/       ← Assembly templates
    └── cve-response.md     ← full CVE-to-rules output
```

## Usage: compose a multi-primitive rule

**Example: Java deserialization (Log4Shell-style)**

1. Load `p1-process-spawn.md` — process spawn from java.exe
2. Load `p7-outbound-connection.md` — outbound from java.exe
3. Load `fallback-or.md` — if network is blind, fall back to spawn only
4. Fill template from `cve-response.md`

Result: complete detection plan with proper fallback and gap documentation.

## When to use fragments vs. patterns

| Scenario | Use |
|---|---|
| Single primitive, well-known | Fragment (lighter, composable) |
| Multiple primitives | Fragments + combinators |
| Complex technique with specific nuances | `detection-patterns/*.md` (full worked examples) |
| CVE response requiring assembly | Fragments + `cve-response.md` template |

*Last updated: 2026-05-28*
