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
    MALDET_OLLAMA_TIMEOUT  default 600 (seconds)
    MALDET_OLLAMA_KEEP_ALIVE  how long the model stays in RAM after a
                              scan; default 60s
    MALDET_OLLAMA_DISABLE  set to 1 to skip the LLM entirely
"""

import os
import re
import collections

import requests

OLLAMA_HOST    = os.environ.get("MALDET_OLLAMA_HOST", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL   = os.environ.get("MALDET_OLLAMA_MODEL", "qwen3.5:2b")
OLLAMA_TIMEOUT = int(os.environ.get("MALDET_OLLAMA_TIMEOUT", "600"))

# How many (tool, issue_text) groups reach the prompt. Fifteen keeps the
# prompt near ~600 tokens, which matters because this is expected to run on
# CPU — the dev machine has no GPU, where generation is seconds per sentence.
MAX_GROUPS = 15

# Reserved slots per risk axis, so one axis cannot crowd out the other. The
# malware share is deliberately close to half despite malicious-pattern
# findings being ~2% of all findings by volume: this is a malware scanner, and
# "ClamAV found a trojan" is more decision-relevant to a visitor than a
# fifteenth insecure-hash warning. Both are capped rather than fixed, and
# _select_groups() hands unused slots back to the other axis.
MAX_MALWARE_GROUPS = 7
MAX_VULN_GROUPS    = 8

# Same weights calculate_risk() uses, so "top findings" here means the same
# thing it means in the score the user is reading next to this summary.
SEVERITY_WEIGHT = {"high": 10, "medium": 3, "low": 1}

# Long enough for a useful paragraph, short enough to bound CPU generation.
# 200 rather than 320: with think=False the whole budget goes to the answer,
# and qwen used it to write 6-9 sentences where the prompt asks for 3-5.
# Fewer tokens also means less generation time, which means less time holding
# ~2.9GB of model in RAM.
MAX_TOKENS = 200

# Context window to allocate, in tokens. qwen3.5:2b declares a context length
# of 262,144 and Ollama sizes its KV cache to the model's declared maximum
# unless told otherwise -- reserving memory for a 262k-token conversation in
# order to write a 200-token paragraph from a ~1,300-token prompt. On a
# 7.9GB machine that over-allocation is what put the user session under
# memory pressure: systemd-oomd killed the Ollama service mid-batch on
# 2026-10-07, 19 summaries into a run of 158.
#
# 4096 is about 3x the largest prompt this builds (1,317 tokens measured for
# LaZagne) plus its output, with room for a repo carrying far more finding
# groups than any in the corpus. Generous rather than tight, because a
# prompt that exceeded it would be silently truncated by Ollama.
NUM_CTX = int(os.environ.get("MALDET_OLLAMA_NUM_CTX", "4096"))

# How long Ollama keeps the model loaded after a request. Its default is 5
# minutes, which on a memory-tight machine means ~2.9GB sits resident long
# after the scan that needed it -- this is what has been triggering
# systemd-oomd on the dev VM. 60s is short enough to free memory promptly,
# long enough that a batch of scans still reuses one load rather than paying
# a cold start (measured: 20-35s warm, up to 290s cold) for every repo.
KEEP_ALIVE = os.environ.get("MALDET_OLLAMA_KEEP_ALIVE", "60s")


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

    scanner.finding_category is imported here rather than at module scope:
    scanner imports this module, so a top-level import is circular and breaks
    `import app` outright.

    Ranked by the same severity weight the risk score uses, multiplied by the
    classifier's confidence that the finding is real — so a high-severity hit
    the model distrusts doesn't outrank a medium one it's sure about.
    """
    from scanner import finding_category

    groups = collections.defaultdict(lambda: {
        "count": 0, "severity": "low", "confidence": 0.0,
        "example_file": "", "example_line": 0, "snippet": "",
        "category": "malicious_pattern",
        # Sort key of the example currently held, as a minimum-wins tuple:
        # (-rank, -confidence, filename, line). See the comparison below.
        "_best": None,
    })

    for f in findings:
        key = (f.get("tool", ""), (f.get("issue_text") or "").strip())
        g   = groups[key]
        g["count"] += 1
        # Same function scanner.py scores with, so the two axes mean the same
        # thing here as they do in the risk levels shown beside this summary.
        g["category"] = finding_category(f)

        severity = (f.get("severity") or "low").lower()
        # Legacy scans stored semgrep's own levels ("error"/"warning"/"info")
        # before normalize_severity() was applied, and SEVERITY_WEIGHT has no
        # entry for them -- so they are already weighted as 1, i.e. low. Label
        # them that way too, instead of telling the model "[semgrep/error]"
        # about a finding the score treats as low. Keeps this agreeing with
        # calculate_risk(), and with the SQL grouping in
        # backfill_summaries.py, which maps the same way.
        if severity not in SEVERITY_WEIGHT:
            severity = "low"
        confidence = f.get("p_real")
        if confidence is None:
            confidence = f.get("confidence")
        confidence = 1.0 if confidence is None else float(confidence)

        # A group's severity is the worst severity in it, and its confidence
        # the highest -- tracked independently.
        #
        # This used to be one condition, "more severe OR more confident",
        # which overwrote both fields together. The comment claimed it broke
        # ties on confidence, but an OR does not break ties: a LOW finding
        # with higher confidence than the current best overwrote severity
        # too, silently downgrading a group that contained a HIGH finding.
        # That mislabelled groups in the prompt and changed their rank, since
        # rank is severity weight times confidence.
        rank = SEVERITY_WEIGHT.get(severity, 1)
        if rank > SEVERITY_WEIGHT.get(g["severity"], 1):
            g["severity"] = severity
        g["confidence"] = max(g["confidence"], confidence)

        # The example shown to the model should be the worst instance:
        # severity first, then confidence. Filename and line are included as
        # a final tie-break so the choice does not depend on the order the
        # findings arrived in -- whole groups routinely tie on severity AND
        # confidence (35 findings of one django group share both), and
        # without this the example cited at scan time differs from the one a
        # regenerated summary cites.
        candidate = (-rank, -confidence,
                     f.get("filename") or "", f.get("line_number") or 0)
        if g["_best"] is None or candidate < g["_best"]:
            g["_best"]        = candidate
            g["example_file"] = f.get("filename") or ""
            g["example_line"] = f.get("line_number") or 0
            g["snippet"]      = (f.get("code_snippet") or "").strip()

    # Tie-broken on (tool, issue_text), not left to input order. Python's
    # sort is stable, so without a tie-break the order of equal-scoring
    # groups follows whatever order the findings arrived in -- which differs
    # between a scan (detector order) and a regenerated summary (database
    # order), and is not guaranteed by MySQL at all without an ORDER BY.
    # That decided which groups fell either side of the 15-group cut: 21 of
    # 162 repos selected a different top 15 depending on the path taken.
    return sorted(
        ({"tool": k[0], "issue_text": k[1], **v} for k, v in groups.items()),
        key=lambda g: (-(SEVERITY_WEIGHT.get(g["severity"], 1)
                         * max(g["confidence"], 0.01)),
                       g["tool"], g["issue_text"]),
    )


def _select_groups(groups):
    """Pick MAX_GROUPS, guaranteeing both risk axes are represented.

    Ranking purely by severity x confidence sounds right but is wrong for a
    malware scanner, because the two axes have wildly different volumes:
    bandit and semgrep produce ~233k findings between them, many high or
    medium, while yara/clamav/guarddog produce a few thousand and are often
    only `low`. The loud vulnerability findings therefore fill every slot and
    push the quiet malicious-pattern ones out.

    Measured on the 179-repo corpus before this change: 82 repos had malware
    findings that never reached the prompt, and in 14 of them *none* did --
    including n1nj4sec/pupy, scored malware=Critical, whose summary was
    written from style warnings while a ClamAV trojan detection sat unsent.
    A plausible-sounding summary that omits the trojan is worse than no
    summary, so each axis gets reserved slots and unused ones are given back.
    """
    vuln_groups = [g for g in groups if g["category"] == "vulnerability"]
    mal_groups  = [g for g in groups if g["category"] == "malicious_pattern"]

    chosen = mal_groups[:MAX_MALWARE_GROUPS] + vuln_groups[:MAX_VULN_GROUPS]

    # Backfill: a repo with no malware findings should still get a full
    # prompt of vulnerability ones, and vice versa.
    if len(chosen) < MAX_GROUPS:
        spare = [g for g in groups if g not in chosen]
        chosen += spare[:MAX_GROUPS - len(chosen)]

    # Restore the global ranking so the model still reads worst-first.
    order = {id(g): i for i, g in enumerate(groups)}
    return sorted(chosen, key=lambda g: order[id(g)])[:MAX_GROUPS]


def _build_prompt(repo_label, findings, vuln, malware):
    """Prompt for a list of raw findings — the scan-time path."""
    return _compose_prompt(repo_label, _rank_groups(findings), len(findings),
                           vuln, malware)


def _compose_prompt(repo_label, groups, total_findings, vuln, malware):
    """Prompt from already-grouped findings.

    Split out from _build_prompt so a summary can be produced from groups
    aggregated by the database instead of from every finding row. That
    matters when the database is remote: a repo can have tens of thousands
    of findings but only a few dozen distinct (tool, issue_text) groups, and
    only the groups are needed here.
    """
    top = _select_groups(groups)

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

{total_findings} findings survived filtering. The most important kinds, already ranked, are:

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


def summarize_groups(repo_label, groups, total_findings, vuln, malware):
    """summarize() for callers that already have grouped findings.

    Same contract: returns None rather than raising, so a caller can keep
    going when Ollama is absent or slow.
    """
    if is_disabled() or not groups:
        return None
    return _generate(_compose_prompt(repo_label, groups, total_findings,
                                     vuln, malware))


def summarize(repo_label, findings, vuln, malware):
    """Return a plain-English summary, or None if the LLM is unavailable.

    None is a normal outcome, not an error — the caller falls back to the
    rule-based summary. Ollama is optional infrastructure.
    """
    if is_disabled() or not findings:
        return None

    return _generate(_build_prompt(repo_label, findings, vuln, malware))


def _generate(prompt):
    """Send one prompt to Ollama and clean up what comes back.

    Shared by summarize() and summarize_groups() so the request options and
    the output guards exist once — a reasoning trace leaking into a stored
    summary is the same hazard whichever path built the prompt.
    """
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
                "keep_alive": KEEP_ALIVE,
                "options": {
                    # Low temperature: this is a factual restatement of a
                    # finished scan, not creative writing.
                    "temperature": 0.2,
                    "num_predict": MAX_TOKENS,
                    "num_ctx": NUM_CTX,
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
    text = " ".join(text.split())

    # MAX_TOKENS is a hard ceiling, so the model can be cut off mid-sentence:
    # one summary in the first three generated ended "...suggests that the
    # codebase is actively vulnerable" with no full stop, which reads as a
    # broken page rather than a short summary. Trim back to the last sentence
    # that actually finished. Raising MAX_TOKENS instead would undo the
    # brevity it was lowered to enforce, and would only move the cut-off.
    if text and text[-1] not in ".!?":
        cut = max(text.rfind(". "), text.rfind("! "), text.rfind("? "))
        # Only trim if a usable summary survives; a stub is worse than a
        # sentence that stops short, and None here means no summary at all.
        if cut >= 120:
            text = text[:cut + 1]

    return text
