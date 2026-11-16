"""
Blind human check of the agent's training labels.

train_labels.jsonl was written by an LLM. This asks a person to label a
random sample of the same findings without seeing the agent's answer, then
measures how often the two agree. That agreement is what says how far the
labels, and anything trained on them, can be trusted.

    python3 blind_check.py            # label, resumes where you stopped
    python3 blind_check.py --score    # agreement, once you have labelled some

The sample is fixed (SEED), spread across the engines in proportion, and
shown in shuffled order. While labelling, the agent's label and reason are
never read from disk, so they cannot be shown by accident. Answers are saved
after every finding to blind_check.json.
"""

import json
import os
import random
import sys
import textwrap

SAMPLE, LABELS, ANSWERS = "train_sample.json", "train_labels.jsonl", "blind_check.json"
SIZE, SEED = 50, 11
REMOVED = "[removed: credential-like text"

RUBRIC = """\
For each finding, decide whether the tool's claim holds for this code.

  r = real    the claim is true here AND worth a reviewer's look
              (an actual weakness, attack code, a malware sample, a
              dependency with a known advisory or no version at all)
  n = noise   the claim is false here, or true but harmless
              (test or example code, a placeholder, documentation,
              style advice, a library's own data)
  u = unsure  you cannot tell from what is shown
  b = back    redo the previous one          q = save and quit

Judge only from what is shown. There is no trick and no expected ratio.
"""


def pick():
    """The same SIZE findings every run: proportional per engine, shuffled."""
    with open(SAMPLE) as fh:
        sample = [x for x in json.load(fh)
                  if not (x["code_snippet"] or "").startswith(REMOVED)]
    rng = random.Random(SEED)
    by_tool = {}
    for x in sample:
        by_tool.setdefault(x["tool"], []).append(x)
    chosen = []
    for tool in sorted(by_tool):
        rows = by_tool[tool]
        rng.shuffle(rows)
        chosen += rows[:max(1, round(SIZE * len(rows) / len(sample)))]
    rng.shuffle(chosen)
    return chosen[:SIZE]


def repo_names(ids):
    """repo_id -> owner/name, or {} when the database is not reachable."""
    try:
        from db_connect import connect
        db = connect()
        try:
            cur = db.cursor()
            cur.execute("SELECT id, owner, repo_name FROM repositories WHERE id IN (%s)"
                        % ",".join(str(int(i)) for i in ids))
            return {r[0]: f"{r[1]}/{r[2]}" for r in cur.fetchall()}
        finally:
            db.close()
    except Exception:
        return {}


def load_answers():
    if not os.path.exists(ANSWERS):
        return {}
    with open(ANSWERS) as fh:
        return json.load(fh)


def save_answers(answers):
    with open(ANSWERS, "w") as fh:
        json.dump(answers, fh, indent=2)


def show(n, total, x, repo):
    print("\n" + "=" * 78)
    print(f"Finding {n} of {total}")
    print(f"  Engine    : {x['tool']}   (severity {x['severity_norm']})")
    if repo:
        print(f"  Repository: {repo}")
    line = f":{x['line_number']}" if x.get("line_number") else ""
    print(f"  File      : {x['filename']}{line}")
    print("  The tool says:")
    print(textwrap.fill(x["issue_text"], 74, initial_indent="    ", subsequent_indent="    "))
    code = (x["code_snippet"] or "").strip()
    if code:
        print("  Code it flagged:")
        for row in code[:700].splitlines()[:14]:
            print("    | " + row[:110])
    else:
        print("  (No code stored: this engine matched the whole file. Judge from the\n"
              "   tool's message and the file's name and folder.)")


def label():
    chosen = pick()
    names = repo_names({x["repo_id"] for x in chosen})
    answers = load_answers()
    print(RUBRIC)
    i = next((k for k, x in enumerate(chosen) if str(x["id"]) not in answers), len(chosen))
    while i < len(chosen):
        x = chosen[i]
        show(i + 1, len(chosen), x, names.get(x["repo_id"]))
        try:
            key = input("  real / noise / unsure / back / quit  [r/n/u/b/q]: ").strip().lower()[:1]
        except (EOFError, KeyboardInterrupt):
            key = "q"
        if key == "q":
            break
        if key == "b":
            i = max(0, i - 1)
            continue
        if key not in ("r", "n", "u"):
            print("  Type r, n, u, b or q.")
            continue
        answers[str(x["id"])] = {"r": "real", "n": "noise", "u": "unsure"}[key]
        save_answers(answers)
        i += 1
    done = sum(1 for x in chosen if str(x["id"]) in answers)
    print(f"\nSaved {done} of {len(chosen)} to {ANSWERS}."
          + ("  Now run: python3 blind_check.py --score" if done == len(chosen) else
             "  Run the same command to continue."))


def score():
    chosen = {x["id"]: x for x in pick()}
    answers = {int(k): v for k, v in load_answers().items() if int(k) in chosen}
    with open(LABELS) as fh:
        agent = {r["id"]: r for r in map(json.loads, filter(str.strip, fh))}
    judged = {i: v for i, v in answers.items() if v != "unsure"}
    if not judged:
        print("Nothing labelled yet. Run: python3 blind_check.py")
        return
    pairs = [(v, agent[i]["label"]) for i, v in judged.items()]
    n = len(pairs)
    agree = sum(a == b for a, b in pairs)
    # Cohen's kappa: agreement beyond what two labellers with these
    # real/noise rates would reach by chance.
    p_o = agree / n
    h_real = sum(a == "real" for a, _ in pairs) / n
    a_real = sum(b == "real" for _, b in pairs) / n
    p_e = h_real * a_real + (1 - h_real) * (1 - a_real)
    kappa = (p_o - p_e) / (1 - p_e) if p_e < 1 else 1.0

    print(f"Labelled {len(answers)} of {len(chosen)} "
          f"({len(answers) - n} marked unsure and left out)\n")
    print(f"Agreement with the agent : {agree} of {n} ({p_o:.0%})")
    print(f"Cohen's kappa            : {kappa:.2f}   "
          "(below 0.4 weak, 0.4-0.6 moderate, 0.6-0.8 substantial, above 0.8 strong)\n")
    print("                    agent: real   agent: noise")
    for mine in ("real", "noise"):
        row = [sum(1 for a, b in pairs if a == mine and b == theirs) for theirs in ("real", "noise")]
        print(f"  you: {mine:<6}        {row[0]:>6}   {row[1]:>12}")
    diff = [i for i, v in judged.items() if v != agent[i]["label"]]
    if diff:
        print(f"\nThe {len(diff)} you disagreed on:")
        for i in diff:
            x = chosen[i]
            print(f"\n  {x['tool']}  {x['filename']}")
            print(f"    {x['issue_text'][:110]}")
            print(f"    you: {judged[i]}   agent: {agent[i]['label']} ({agent[i]['reason']})")


if __name__ == "__main__":
    score() if "--score" in sys.argv else label()
