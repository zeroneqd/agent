# Combinator: Sequence-AND

> Combine two or more primitives that must occur in sequence within a time window.
> Higher fidelity than OR — catches coordinated multi-step behavior.

## Template

```kql
let {{window_name}} = {{time_window}};
let PrimitiveA = materialize (
    {{detection_block_A}}
    | project Timestamp, DeviceId, KeyA={{join_key_A}}
);
let PrimitiveB = materialize (
    {{detection_block_B}}
    | project Timestamp, DeviceId, KeyB={{join_key_B}}
);
PrimitiveA
| join kind=inner (PrimitiveB) on DeviceId
| where datetime_diff('minute', TimestampB, Timestamp) between (0 .. {{window_minutes}})
| project DeviceName, FirstPrimitive={{label_A}}, FirstTime=Timestamp,
    SecondPrimitive={{label_B}}, SecondTime=TimestampB,
    DeviceId
```

## Parameters

| Parameter | Description | Default |
|---|---|---|
| `time_window` | Lookback for each primitive | `24h` |
| `window_minutes` | Max minutes between A and B | `5` |
| `join_key_A/B` | Keys to correlate (usually `InitiatingProcessSHA1` or `AccountSid`) | `InitiatingProcessSHA1` |
| `label_A/B` | Human-readable primitive names | — |

## Example: Process injection followed by network connection

```kql
let TimeWindow = 5m;
let Injection = materialize (
    DeviceEvents
    | where Timestamp > ago(24h)
    | where ActionType in ("WriteProcessMemoryApiCall", "CreateRemoteThreadApiCall")
    | project Timestamp, DeviceId, DeviceName, Injector=InitiatingProcessFileName
);
let Network = materialize (
    DeviceNetworkEvents
    | where Timestamp > ago(24h)
    | where ActionType == "ConnectionSuccess"
    | where ipv4_is_private(RemoteIP) == false
    | project Timestamp, DeviceId, RemoteIP, RemotePort
);
Injection
| join kind=inner (Network) on DeviceId
| where datetime_diff('minute', Timestamp1, Timestamp) between (0 .. 5)
| project DeviceName, Injector, InjectionTime=Timestamp,
    RemoteIP, RemotePort, NetworkTime=Timestamp1
| order by InjectionTime desc
```

## When to use

- Two primitives from the SAME process / device within minutes
- Higher fidelity than either primitive alone
- Good for: injection → spawn, spawn → network, drop → execution

## Performance notes

- `materialize()` is essential — both primitives may be used multiple times
- Keep window tight (5m default) — wider windows increase join cardinality
- Filter both sides aggressively before joining
