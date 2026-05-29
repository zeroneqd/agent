"""Router — deterministic decision tree for path selection.

Used by `detection-helper.agent.md` Step 0 as an advisory hint: a single
function call, zero LLM tokens for routing. The returned `agent` field is an
internal path label (threat-translator=A, defender-telemetry=B,
detection-author=C, ask-clarify=D), not a separate agent to hand off to.

Usage:
    from tools.router import route
    decision = route("Detect LSASS dumping")
    # → {"agent": "detection-author", "reason": "...", "pipeline_depth": 1}
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
URL_RE = re.compile(r"https?://\S+")

# Generic standalone words that are NOT follow-ups even when short / in-session.
NON_FOLLOWUP_WORDS = {
    "help", "detection", "detect", "hello", "hi", "hey", "thanks",
    "thank you", "yes", "no", "ok", "okay",
}
# Question stems that signal a fresh standalone question, not a terse follow-up.
QUESTION_STEMS = {"what", "how", "why", "is", "are", "can", "should", "where", "which", "who"}

# Weighted keyword lists — order matters (more specific first)
TELEMETRY_PATTERNS = [
    "is.*logged", "which table", "which column", "what column",
    "where is.*logged", "actiontype", "event id", "translate.*sentinel",
    "translate.*splunk", "verify.*actiontype", "tenant.*observed",
    "which.*event id", "how.*logged", "schema.*overview",
]

PATTERN_PATTERNS = [
    "detect lsass", "credential dump", "scheduled task abuse",
    "process injection", "lolbin abuse", "rdp lateral",
    "kerberoasting", "wmi persistence", "service install",
    "rule for", "detection for", "kql for", "query for",
    "detection rule", "hunt for", "alert on",
    # Service control / tampering verbs
    "stop.*service", "stopping.*service", "disable.*service", "delete.*service",
    "remove.*service", "modify.*service", "service.*stop", "service.*disabl",
    "service.*delet", "services.msc", "sc stop", "sc delete", "net stop",
]

FOLLOWUP_PATTERNS = [
    "what about", "and for", "also", "additionally",
    "what if", "how about", "can you also",
]

# Explicit command prefixes. Authoritative: when present they override all
# keyword heuristics. Maps the prefix verb -> (agent, pipeline_depth, reason, tools).
# Multiple spellings point at the same route so users don't have to memorize one form.
PREFIX_ROUTES = {
    # Threat intel, decompose ONLY — stop at the plan, do not auto-author rules.
    "intel": ("threat-translator", 1, "Explicit prefix: intel (decompose only, no rule authoring)",
              ["telemetry", "primitives", "confidence", "session"]),
    "threat": ("threat-translator", 1, "Explicit prefix: threat (decompose only, no rule authoring)",
               ["telemetry", "primitives", "confidence", "session"]),
    # Full chain: decompose -> telemetry -> author + validate.
    "pipeline": ("threat-translator", 3, "Explicit prefix: pipeline (full chain A->B->C)",
                 ["telemetry", "primitives", "confidence", "session", "patterns", "validator"]),
    "full": ("threat-translator", 3, "Explicit prefix: full (full chain A->B->C)",
             ["telemetry", "primitives", "confidence", "session", "patterns", "validator"]),
    # Telemetry lookup only.
    "event": ("defender-telemetry", 1, "Explicit prefix: event (telemetry lookup only)",
              ["telemetry", "confidence"]),
    "telemetry": ("defender-telemetry", 1, "Explicit prefix: telemetry (telemetry lookup only)",
                  ["telemetry", "confidence"]),
    # Verify telemetry, then author + validate a rule.
    "rule": ("detection-author", 1, "Explicit prefix: rule (verify telemetry, then author + validate)",
             ["telemetry", "patterns", "confidence", "validator"]),
    "detect": ("detection-author", 1, "Explicit prefix: detect (verify telemetry, then author + validate)",
               ["telemetry", "patterns", "confidence", "validator"]),
}


class Agent(Enum):
    ROUTER = "router"
    THREAT_TRANSLATOR = "threat-translator"
    DEFENDER_TELEMETRY = "defender-telemetry"
    DETECTION_AUTHOR = "detection-author"
    ASK_CLARIFY = "ask-clarify"


@dataclass
class RouteDecision:
    agent: str
    reason: str
    pipeline_depth: int  # 0=ask, 1=single agent, 3=full pipeline
    load_tools: list[str]  # which Python tools to load


def route(
    user_input: str,
    session_status: str = "empty",
    conversation_history: list[str] | None = None,
) -> RouteDecision:
    """Route user input to the correct agent.

    Rules (applied in order):
    1. CVE or threat URL → threat-translator (full pipeline)
    2. Simple telemetry question → defender-telemetry (direct)
    3. Known-pattern detection → detection-author (direct)
    4. Follow-up with active session or conversation context → continue
    5. Ambiguous → ask clarifying question

    Args:
        user_input: The current query
        session_status: Pipeline status from Session
        conversation_history: Prior user messages for context detection
    """
    text = user_input.lower().strip()
    history = [h.lower() for h in (conversation_history or [])]

    # Rule 0: explicit command prefix wins over everything ("rule: ...", "intel: ...").
    prefixed = _prefix_route(user_input)
    if prefixed is not None:
        return prefixed

    # Rule 1: CVE or threat URL
    if _has_cve(user_input) or _has_url(user_input):
        return RouteDecision(
            agent=Agent.THREAT_TRANSLATOR.value,
            reason="CVE ID or threat intel URL detected",
            pipeline_depth=3,
            load_tools=["telemetry", "primitives", "confidence", "session"],
        )

    # Rule 2: Simple telemetry question
    if _matches_any(text, TELEMETRY_PATTERNS):
        return RouteDecision(
            agent=Agent.DEFENDER_TELEMETRY.value,
            reason="Simple telemetry lookup query",
            pipeline_depth=1,
            load_tools=["telemetry", "confidence"],
        )

    # Rule 3: Known-pattern detection request
    if _matches_any(text, PATTERN_PATTERNS):
        return RouteDecision(
            agent=Agent.DETECTION_AUTHOR.value,
            reason="Known-pattern detection request",
            pipeline_depth=1,
            load_tools=["telemetry", "patterns", "confidence", "validator"],
        )

    # Rule 4a: Anaphora detection ("what about Linux?", "and for Splunk?")
    if history and _is_anaphoric(text):
        return RouteDecision(
            agent=_continuation_agent(session_status) if session_status not in ("empty", "")
            else Agent.DEFENDER_TELEMETRY.value,
            reason=f"Anaphoric follow-up (refers to: ...{history[-1][-40:]})",
            pipeline_depth=1,
            load_tools=["session", "telemetry", "confidence"],
        )

    # Rule 4b: Active session follow-up
    if session_status not in ("empty", "") and _is_followup(text):
        return RouteDecision(
            agent=_continuation_agent(session_status),
            reason=f"Follow-up to active session (status: {session_status})",
            pipeline_depth=1,
            load_tools=["session", "telemetry", "confidence"],
        )

    # Rule 5: Ambiguous
    return RouteDecision(
        agent=Agent.ASK_CLARIFY.value,
        reason="Ambiguous query — need behavior, platform, or CVE",
        pipeline_depth=0,
        load_tools=[],
    )


def _prefix_route(user_input: str):
    """Return a RouteDecision if the input opens with a known command prefix.

    A prefix is a leading word followed by ':' (e.g. "rule: stop a service").
    Unknown prefixes return None so normal keyword routing still applies.
    """
    m = re.match(r"\s*([a-zA-Z]+)\s*:\s*(.*)", user_input, re.DOTALL)
    if not m:
        return None
    verb = m.group(1).lower()
    payload = m.group(2).strip()
    spec = PREFIX_ROUTES.get(verb)
    if spec is None or not payload:
        return None
    agent, depth, reason, tools = spec
    return RouteDecision(agent=agent, reason=reason, pipeline_depth=depth, load_tools=tools)


def _is_anaphoric(text: str) -> bool:
    """Detect follow-ups that refer to previous context via pronouns."""
    anaphora = [
        r"^what about", r"^and ", r"^how about",
        r"^(what|how) (is|are|does|about)",
        r"\bit\b.*\blogged\b", r"\bthat\b.*\btable\b",
    ]
    return any(re.search(p, text) for p in anaphora)


def _has_cve(text: str) -> bool:
    return bool(CVE_RE.search(text))


def _has_url(text: str) -> bool:
    return bool(URL_RE.search(text))


def _matches_any(text: str, patterns: list[str]) -> bool:
    for p in patterns:
        if re.search(p, text):
            return True
    return False


def _is_followup(text: str) -> bool:
    """A follow-up is an explicit cue ("what about", "also") or a terse fragment
    that only makes sense against prior context (e.g. "Linux?", "and Splunk").

    Only called when a session is already active. We avoid the old `len < 20`
    rule, which misrouted short standalone queries like "help" or "detection".
    """
    if any(re.search(p, text) for p in FOLLOWUP_PATTERNS):
        return True
    stripped = text.rstrip("?").strip()
    if not stripped or len(stripped) >= 20:
        return False
    if stripped in NON_FOLLOWUP_WORDS:
        return False
    # A fresh wh-/aux- question is standalone, not a fragment follow-up.
    if stripped.split()[0] in QUESTION_STEMS:
        return False
    return True


def _continuation_agent(session_status: str) -> str:
    if session_status in ("decomposed",):
        return Agent.DEFENDER_TELEMETRY.value
    if session_status in ("telemetry_confirmed",):
        return Agent.DETECTION_AUTHOR.value
    return Agent.THREAT_TRANSLATOR.value


# ── CLI ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys, json
    query = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "Detect LSASS credential dumping"
    d = route(query)
    print(json.dumps({
        "query": query,
        "agent": d.agent,
        "reason": d.reason,
        "pipeline_depth": d.pipeline_depth,
        "load_tools": d.load_tools,
    }, indent=2))
