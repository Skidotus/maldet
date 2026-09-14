"""
Terminal review tool for eval_sample.json — the hand-checked evaluation set
for the ML classifier (see NOTES.md, "Build a small hand-labeled evaluation
holdout"). Every entry already has an AI-suggested label + a one-sentence
reason (see build_eval_sample.py / the labeling pass that filled them in).
Your job here is just to confirm or overrule each one — you're reviewing,
not starting from a blank slate.

Progress is saved after every single answer, so it's safe to quit (q) and
resume later — already-reviewed entries are skipped automatically.

Run standalone: `python3 review_labels.py`
"""

import json
import os

PATH = "eval_sample.json"


def load():
    with open(PATH) as f:
        return json.load(f)


def save(data):
    with open(PATH, "w") as f:
        json.dump(data, f, indent=2)


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def main():
    data = load()
    todo = [d for d in data if not d.get("human_label")]
    total = len(data)
    done_at_start = total - len(todo)

    if not todo:
        print(f"All {total} findings already reviewed. Run evaluate_classifier.py next.")
        return

    print(f"{done_at_start}/{total} already reviewed. {len(todo)} left.\n")
    input("Press Enter to start...")

    for i, d in enumerate(todo, 1):
        clear()
        print(f"[{done_at_start + i}/{total}]")
        print("-" * 70)
        print(f"Tool:      {d['tool']}")
        print(f"Severity:  {d['severity']}")
        print(f"File:      {d['filename']}" + (f":{d['line_number']}" if d.get('line_number') else ""))
        print(f"Finding:   {d['issue_text']}")
        if d.get("code_snippet"):
            print(f"Code:\n    {d['code_snippet']}")
        print("-" * 70)
        print(f"AI suggests: {d['ai_suggested_label'].upper()}")
        print(f"Reason:      {d['ai_reason']}")
        print("-" * 70)

        while True:
            ans = input(
                "\n[Enter]=agree   r=mark REAL   n=mark NOISE   s=skip   q=save & quit  > "
            ).strip().lower()
            if ans == "":
                d["human_label"] = d["ai_suggested_label"]
                break
            elif ans == "r":
                d["human_label"] = "real"
                break
            elif ans == "n":
                d["human_label"] = "noise"
                break
            elif ans == "s":
                break
            elif ans == "q":
                save(data)
                remaining = sum(1 for x in data if not x.get("human_label"))
                print(f"\nSaved. {total - remaining}/{total} reviewed, {remaining} left.")
                return
            else:
                print("  Please type Enter, r, n, s, or q.")

        save(data)  # save after every answer so nothing is lost

    remaining = sum(1 for x in data if not x.get("human_label"))
    clear()
    print(f"Done! {total - remaining}/{total} reviewed.")
    if remaining == 0:
        print("Every finding is labeled — run: python3 evaluate_classifier.py")


if __name__ == "__main__":
    main()
