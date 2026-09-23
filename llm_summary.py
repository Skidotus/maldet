"""
Plain-English summary of a scan's findings, written by a local LLM.

Every detector in this project already normalises its output to the same
shape — `{tool, severity, issue_text, filename, line_number, code_snippet}`
plus the classifier's `confidence` — so summarising "the output of Bandit,
YARA, Semgrep, ClamAV, GuardDog and dep_checker" is just summarising one
uniform list. That normalisation is what makes this cheap to add.

Two deliberate boundaries:

  1. **It explains, it does not score.** The Random Forest decides what's
     real and `calculate_risk()` decides how bad it is, both before this
     runs. The LLM only puts the result into words. Letting it score would
     replace a measured component (precision 0.52 / recall 0.62 against a
     hand-reviewed holdout) with an unmeasured one.

  2. **It sees the top findings, not all of them.** A single repo can
     produce tens of thousands; LaZagne alone yields 260 after filtering.
     Findings are grouped by (tool, issue_text) and only the highest-ranked
     groups are sent, which also tells the model "this fired 43 times"
     instead of making it count 43 near-identical lines.

Everything here degrades to None rather than raising: if Ollama isn't
installed, isn't running, is slow, or returns something unusable, the caller
falls back to the rule-based summary in app.py. A scan must never fail
because an optional explainer was unavailable.

Setup (no API key, runs locally):
    curl -fsSL https://ollama.com/install.sh | sh
    ollama pull qwen3.5:2b

Configuration, all optional:
    MALDET_OLLAMA_HOST     default http://localhost:11434
    MALDET_OLLAMA_MODEL    default qwen3.5:2b
    MALDET_OLLAMA_TIMEOUT  default 300 (seconds)
    MALDET_OLLAMA_DISABLE  set to 1 to skip the LLM entirely
"""

import os
import re
import collections

import requests

OLLAMA_HOST    = os.environ.get("MALDET_OLLAMA_HOST", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL   = os.environ.get("MALDET_OLLAMA_MODEL", "qwen3.5:2b")
OLLAMA_TIMEOUT = int(os.environ.get("MALDET_OLLAMA_TIMEOUT", "300"))

# How many (tool, issue_text) groups reach the prompt. Fifteen keeps the
# prompt near ~600 tokens, which matters because this is expected to run on
# CPU — the dev machine has no GPU, where generation is seconds per sentence.
MAX_GROUPS = 15

# Same weights calculate_risk() uses, so "top findings" here means the same
# thing it means in the score the user is reading next to this summary.
SEVERITY_WEIGHT = {"high": 10, "medium": 3, "low": 1}

# Long enough for a useful paragraph, short enough to bound CPU generation.
MAX_TOKENS = 320


def is_disabled():
    return os.environ.get("MALDET_OLLAMA_DISABLE", "") == "1"


def is_available():
    """True if an Ollama server is reachable and has the configured model."""
    if is_disabled():
        return False
    try:
        resp = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
        resp.raise_for_status()
        names = [m.get("name", "") for m in resp.json().get("models", [])]
    except Exception:
        return False
    # Ollama reports "qwen3.5:2b"; accept a bare "qwen3.5" as configured too.
    return any(n == OLLAMA_MODEL or n.split(":")[0] == OLLAMA_MODEL.split(":")[0]
               for n in names)


def _rank_groups(findings):
    """Collapse findings into (tool, issue_text) groups, most important first.

    Ranked by the same severity weight the risk score uses, multiplied by the
    classifier's confidence that the finding is real — so a high-severity hit
    the model distrusts doesn't outrank a medium one it's sure about.
    """
    groups = collections.defaultdict(lambda: {
        "count": 0, "severity": "low", "confidence": 0.0,
        "example_file": "", "example_line": 0, "snippet": "",
    })

    for f in findings:
        key = (f.get("tool", ""), (f.get("issue_text") or "").strip())
        g   = groups[key]
        g["count"] += 1

        severity   = (f.get("severity") or "low").lower()
        confidence = f.get("p_real")
        if confidence is None:
            confidence = f.get("confidence")
        confidence = 1.0 if confidence is None else float(confidence)

        # Keep the most severe example, breaking ties on confidence, so the
        # file path shown to the model is the worst instance rather than
        # whichever happened to be scanned first.
        if (SEVERITY_WEIGHT.get(severity, 1) > SEVERITY_WEIGHT.get(g["severity"], 1)
                or confidence > g["confidence"]):
            g["severity"]     = severity
            g["confidence"]   = confidence
            g["example_file"] = f.get("filename") or ""
            g["example_line"] = f.get("line_number") or 0
            g["snippet"]      = (f.get("code_snippet") or "").strip()

    ranked = sorted(
        ({"tool": k[0], "issue_text": k[1], **v} for k, v in groups.items()),
        key=lambda g: SEVERITY_WEIGHT.get(g["severity"], 1) * max(g["confidence"], 0.01),
        reverse=True,
    )
    return ranked


def _build_prompt(repo_label, findings, vuln, malware):
    groups = _rank_groups(findings)
    top    = groups[:MAX_GROUPS]

    lines = []
    for g in top:
        location = g["example_file"] or "unknown file"
        if g["example_line"]:
            location += f":{g['example_line']}"
        times = f" (seen {g['count']} times)" if g["count"] > 1 else ""
        text  = g["issue_text"][:200]
        lines.append(
            f"- [{g['tool']}/{g['severity']}] {text}{times}; "
            f"example {location}; classifier confidence "
            f"{round(g['confidence'] * 100)}%"
        )

    remaining = len(groups) - len(top)
    if remaining > 0:
        lines.append(f"- (plus {remaining} other kinds of finding, lower priority)")

    findings_block = "\n".join(lines)

    # The scores are given as already-decided facts. The model is told not to
    # re-rate them, because a fluent model will happily contradict a measured
    # number if the prompt leaves it room to.
    return f"""You are helping a developer understand a security scan of the public GitHub repository {repo_label}.

The scan has ALREADY been completed and scored. Two separate scores were produced:

- Vulnerability risk: {vuln['level']} (score {vuln['score']}) — insecure coding patterns that an attacker could exploit. Reported by Bandit and Semgrep.
- Malicious-pattern risk: {malware['level']} (score {malware['score']}) — signs the code may be intentionally malicious. Reported by YARA, ClamAV, GuardDog and the dependency checker.

{len(findings)} findings survived filtering. The most important kinds, already ranked, are:

{findings_block}

Write a short plain-English summary for a developer deciding whether this repository is safe to use. Requirements:
- 3 to 5 sentences, one paragraph, no headings, no bullet points, no markdown.
- Lead with what matters most and what it means in practice.
- Say plainly if the findings look like ordinary insecure coding rather than malicious intent, or the other way round.
- Use ONLY the findings and scores above. Do not invent findings, file names or CVE numbers.
- The scores have no maximum. Quote a score as a plain number if you mention it; never write it as "out of" some total.
- Do not re-rate the risk or disagree with the scores given; they were decided by a separate measured model.
- Write for someone who is not a security expert. Avoid jargon where a plain word works."""


def _strip_markdown(text):
    """Remove markdown the prompt already asked the model not to use.

    The template renders the summary as plain text ({{ llm_summary }}), so
    Flask does not translate markdown -- backticks and asterisks would show
    up literally on the page and look like a bug in the app. qwen3.5 adds
    backticks around identifiers despite being told not to, so this is not
    hypothetical. Cheap insurance for any model.
    """
    text = re.sub(r"`{1,3}([^`]*)`{1,3}", r"\1", text)      # `code` -> code
    text = re.sub(r"\*{1,3}([^*]+)\*{1,3}", r"\1", text)    # **bold** -> bold
    text = re.sub(r"^\s{0,3}#{1,6}\s*", "", text, flags=re.M)  # headings
    text = re.sub(r"^\s{0,3}[-*+]\s+", "", text, flags=re.M)   # bullets
    return text


def summarize(repo_label, findings, vuln, malware):
    """Return a plain-English summary, or None if the LLM is unavailable.

    None is a normal outcome, not an error — the caller falls back to the
    rule-based summary. Ollama is optional infrastructure.
    """
    if is_disabled() or not findings:
        return None

    prompt = _build_prompt(repo_label, findings, vuln, malware)
    try:
        resp = requests.post(
            f"{OLLAMA_HOST}/api/generate",
            json={
                "model":  OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                # Reasoning models (qwen3.5, granite4.x) think out loud before
                # answering. Left on, qwen spends the whole num_predict budget
                # thinking and returns an EMPTY response, while granite writes
                # its reasoning straight into the answer -- which would be
                # stored and shown to the user as if it were the summary.
                # Non-reasoning models accept and ignore this, so it is safe
                # to send unconditionally.
                "think": False,
                "options": {
                    # Low temperature: this is a factual restatement of a
                    # finished scan, not creative writing.
                    "temperature": 0.2,
                    "num_predict": MAX_TOKENS,
                },
            },
            timeout=OLLAMA_TIMEOUT,
        )
        resp.raise_for_status()
        text = (resp.json().get("response") or "").strip()
    except Exception as e:
        print(f"    LLM summary unavailable ({type(e).__name__}), using rule-based fallback")
        return None

    if not text:
        return None

    # Small models sometimes open with "Here is a summary:" despite being told
    # not to use headings. Drop a leading label line rather than showing it.
    first, _, rest = text.partition("\n")
    if rest.strip() and len(first) < 60 and first.rstrip().endswith(":"):
        text = rest.strip()

    # A reasoning trace that slipped through despite think=False is worse than
    # no summary: it reads like prose, so it would be stored and displayed as
    # the answer. Recognise the model talking to itself about the task and
    # fall back to the rule-based text instead.
    lowered = text[:200].lower()
    if any(p in lowered for p in ("we need to", "the user asked", "let me",
                                 "first, i", "thinking process", "i need to")):
        print("    LLM summary looked like a reasoning trace, using rule-based fallback")
        return None

    text = _strip_markdown(text)
    return " ".join(text.split())
