"""Metrics — per-query token estimation and savings tracking.

Logs prompt sizes and estimated token savings to JSON for ROI measurement.

Usage:
    from tools.metrics import estimate_tokens, log_query
    estimate = estimate_tokens(prompt_lines=100, tools_used=3)
    log_query(agent="telemetry", prompt_lines=100, tools_used=3)
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

METRICS_PATH = Path(__file__).resolve().parent.parent / "docs" / "session" / "metrics.json"

# Estimated tokens per line of markdown prose
TOKENS_PER_LINE = 1.5

# Baseline prompt sizes by version (measured)
BASELINE_V3 = 1069  # lines across 3 monolithic agents
BASELINE_V4 = 359   # lines across 4 thin orchestrators
BASELINE_V5 = 334   # lines with Python tools


def estimate_tokens(prompt_lines: int, tools_used: int = 0) -> dict:
    """Estimate token count and savings vs. baseline versions.

    Args:
        prompt_lines: Lines in the agent prompt actually sent to LLM
        tools_used: Number of Python tools invoked (each saves ~N lines)

    Returns:
        {
            "estimated_tokens": float,
            "vs_v3_savings_lines": int,
            "vs_v3_savings_tokens": int,
            "vs_v3_savings_pct": float,
            "tools_offloaded": int,
        }
    """
    estimated_tokens = prompt_lines * TOKENS_PER_LINE
    vs_v3_lines = BASELINE_V3 - prompt_lines
    vs_v3_tokens = vs_v3_lines * TOKENS_PER_LINE
    vs_v3_pct = (vs_v3_lines / BASELINE_V3 * 100) if BASELINE_V3 > 0 else 0

    return {
        "estimated_tokens": round(estimated_tokens, 1),
        "vs_v3_savings_lines": vs_v3_lines,
        "vs_v3_savings_tokens": round(vs_v3_tokens, 1),
        "vs_v3_savings_pct": round(vs_v3_pct, 1),
        "tools_offloaded": tools_used,
    }


def log_query(
    agent: str,
    prompt_lines: int,
    tools_used: int = 0,
    pipeline_depth: int = 1,
    query_type: str = "",
) -> None:
    """Log a query metrics entry."""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "agent": agent,
        "pipeline_depth": pipeline_depth,
        "query_type": query_type,
        **estimate_tokens(prompt_lines, tools_used),
    }

    data = _load()
    data["queries"].append(entry)
    data["summary"][_summary_key(pipeline_depth)] += 1
    _save(data)


def get_summary() -> dict:
    """Return aggregate metrics."""
    data = _load()
    queries = data.get("queries", [])
    if not queries:
        return {"total_queries": 0}

    total_tools = sum(q.get("tools_offloaded", 0) for q in queries)
    total_savings = sum(q.get("vs_v3_savings_tokens", 0) for q in queries)

    return {
        "total_queries": len(queries),
        "total_tools_offloaded": total_tools,
        "total_token_savings_vs_v3": round(total_savings, 1),
        "avg_tools_per_query": round(total_tools / len(queries), 2),
        "avg_savings_per_query_tokens": round(total_savings / len(queries), 1),
        "by_pipeline_depth": data.get("summary", {}),
    }


def _load() -> dict:
    try:
        with open(METRICS_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            "version": "5.0",
            "baseline_v3_lines": BASELINE_V3,
            "queries": [],
            "summary": {"single_agent": 0, "multi_agent_pipeline": 0, "full_pipeline": 0},
        }


def _save(data: dict) -> None:
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def _summary_key(depth: int) -> str:
    if depth == 1:
        return "single_agent"
    if depth == 3:
        return "full_pipeline"
    return "multi_agent_pipeline"


# ── CLI ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json as _json
    print(_json.dumps(get_summary(), indent=2))
