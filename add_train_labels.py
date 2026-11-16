"""Appends agent labels to train_labels.jsonl.

Reads "index|label|reason" lines on stdin, where index is the position in
train_sample.json, and refuses a finding that is already labelled or a
label that is not real/noise.

    python3 add_train_labels.py <labeller> < batch.txt
    python3 add_train_labels.py --show 50 150     # print findings to label
"""

import json
import sys

SAMPLE, LABELS = "train_sample.json", "train_labels.jsonl"


def labelled_ids():
    try:
        with open(LABELS) as fh:
            return {json.loads(l)["id"] for l in fh if l.strip()}
    except FileNotFoundError:
        return set()


def show(start, end):
    with open(SAMPLE) as fh:
        sample = json.load(fh)
    for i, x in enumerate(sample[start:end], start):
        code = (x["code_snippet"] or "").strip().replace("\n", "\\n")[:220]
        print(f"#{i} {x['tool']}/{x['severity_norm']} {x['filename']}:{x['line_number']}\n"
              f"  R: {x['issue_text'][:170]}\n  C: {code}")


def add(labeller):
    with open(SAMPLE) as fh:
        sample = json.load(fh)
    done = labelled_ids()
    out = []
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        index, label, reason = line.split("|", 2)
        finding = sample[int(index)]
        if label not in ("real", "noise"):
            sys.exit(f"line {index}: label must be real or noise, got {label!r}")
        if finding["id"] in done:
            sys.exit(f"line {index}: finding {finding['id']} is already labelled")
        done.add(finding["id"])
        out.append({"id": finding["id"], "label": label, "reason": reason, "labeller": labeller})
    with open(LABELS, "a") as fh:
        for row in out:
            fh.write(json.dumps(row) + "\n")
    with open(LABELS) as fh:
        rows = [json.loads(l) for l in fh if l.strip()]
    print(f"added {len(out)}; {len(rows)} of {len(sample)} labelled, "
          f"{sum(r['label'] == 'real' for r in rows)} real")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--show":
        show(int(sys.argv[2]), int(sys.argv[3]))
    elif len(sys.argv) == 2:
        add(sys.argv[1])
    else:
        sys.exit(__doc__)
