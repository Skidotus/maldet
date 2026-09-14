"""
Computes real precision/recall/F1 for the ML classifier (train_classifier.py)
against eval_sample.json's human_label field — the hand-checked ground truth
that train_classifier.py's own weak-label test set can't provide (see
NOTES.md, "Build a small hand-labeled evaluation holdout").

"Real" = the finding's own p_real/confidence >= REAL_THRESHOLD (same 0.5
cutoff app.py already uses to mark a finding "likely real" in the UI).

Also reports what a "trust every finding equally" baseline (the pre-ML
scoring approach) would have scored, so the classifier's actual value-add
is visible, not just its raw accuracy number.

Run after review_labels.py has labeled every entry:
`python3 evaluate_classifier.py`
"""

import json
from collections import Counter

from sklearn.metrics import classification_report, confusion_matrix

REAL_THRESHOLD = 0.5

with open("eval_sample.json") as f:
    data = json.load(f)

unreviewed = [d for d in data if not d.get("human_label")]
if unreviewed:
    print(f"{len(unreviewed)}/{len(data)} findings still unreviewed — "
          f"run review_labels.py first for a complete picture.\n"
          f"Evaluating on the {len(data) - len(unreviewed)} reviewed so far.\n")

reviewed = [d for d in data if d.get("human_label")]
if not reviewed:
    print("Nothing reviewed yet.")
    raise SystemExit

y_true = [1 if d["human_label"] == "real" else 0 for d in reviewed]
y_pred = [1 if (d["confidence"] or 0) >= REAL_THRESHOLD else 0 for d in reviewed]

print("=" * 70)
print(f"Overall — {len(reviewed)} hand-reviewed findings, threshold={REAL_THRESHOLD}")
print("=" * 70)
print(classification_report(y_true, y_pred, target_names=["noise", "real"], zero_division=0))
print("Confusion matrix (rows=your judgment, cols=model's prediction) [noise, real]:")
print(confusion_matrix(y_true, y_pred))

agree_with_ai = sum(1 for d in reviewed if d["human_label"] == d["ai_suggested_label"])
print(f"\nYou agreed with the AI's suggested label on "
      f"{agree_with_ai}/{len(reviewed)} ({agree_with_ai/len(reviewed)*100:.1f}%) findings.")

print("\n" + "=" * 70)
print("Per-tool breakdown")
print("=" * 70)
for tool in sorted(set(d["tool"] for d in reviewed)):
    subset = [d for d in reviewed if d["tool"] == tool]
    yt = [1 if d["human_label"] == "real" else 0 for d in subset]
    yp = [1 if (d["confidence"] or 0) >= REAL_THRESHOLD else 0 for d in subset]
    real_n = sum(yt)
    correct = sum(1 for a, b in zip(yt, yp) if a == b)
    print(f"  {tool:<12} n={len(subset):>3}  real={real_n:>3}  "
          f"model-correct={correct}/{len(subset)} ({correct/len(subset)*100:.0f}%)")

print("\n" + "=" * 70)
print("Baseline comparison: 'trust every finding equally' (pre-classifier approach)")
print("=" * 70)
naive_precision = sum(y_true) / len(y_true) if y_true else 0
print(f"If every finding were treated as real (old behavior, p_real=1.0 for everything):")
print(f"  precision would be {naive_precision:.3f} (= fraction of ALL findings that are actually real)")
print(f"  recall would be 1.000 (catches every real finding, but buries it in noise)")
model_precision = sum(1 for a, b in zip(y_true, y_pred) if a == 1 and b == 1) / max(sum(y_pred), 1)
print(f"\nThe classifier's actual precision at this threshold: {model_precision:.3f}")
