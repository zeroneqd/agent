"""Detection Helper Tools — Deterministic Python modules that replace LLM instructions.

Each module handles a specific concern previously described in agent prompts:
  - telemetry: lookup tables, column validation, anti-pattern detection
  - router: decision tree for agent selection
  - confidence: unified L1-L5 scoring
  - session: JSON state machine for pipeline coordination
  - patterns: fragment-based rule composition
  - validator: cross-agent validation gate
  - primitives: exploit primitive lookup (P1-P12)
  - health: startup validation of entire tool chain
  - metrics: token savings tracking
  - result_types: structured return types for agent consumption

Usage:
    from tools import telemetry, router, confidence, session
    result = telemetry.resolve("process injection")
    level = confidence.compute_level(evidence)
    decision = router.route("Detect LSASS dumping")

Command-line:
    python -m tools.telemetry resolve "process injection"
    python -m tools.router "Detect LSASS dumping"
    python -m tools.health
"""

__version__ = "5.1.0"

# Lazy imports — modules loaded only when accessed
__all__ = [
    "_base",
    "telemetry",
    "router",
    "confidence",
    "session",
    "patterns",
    "validator",
    "primitives",
    "health",
    "metrics",
    "result_types",
]
