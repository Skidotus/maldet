"""
Computes real precision/recall/F1 for the ML classifier (train_classifier.py)
against eval_sample.json's human_label field — the hand-checked ground truth
that train_classifier.py's own weak-label test set can't provide (see
NOTES.md, "Build a small hand-labeled evaluation holdout").

"Real" = p_real >= REAL_THRESHOLD (same 0.5 cutoff app.py uses to mark a
finding "likely real" in the UI).

Findings are re-scored live through scanner.score_findings() — the same code
path a real scan uses — rather than reading the `confidence` value stored in
eval_sample.json. That stored value is a snapshot from whenever the sample
was built, so after any retrain it goes stale, and reading it would report
the accuracy of a model that is no longer the one running. Scoring live means
this always measures the model currently in model/risk_classifier.pkl.

Also reports what a "trust every finding equally" baseline (the pre-ML
scoring approach) would have scored, so the classifier's actual value-add
is visible, not just its raw accuracy number.

Run after review_labels.py has labeled every entry:
`python3 evaluate_classifier.py`
"""

import json

from sklearn.metrics import classification_report, confusion_matrix

from scanner import score_findings

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

# Score through the live pipeline. score_findings() mutates in place and
# sets f["p_real"], and it falls back to 1.0 for every finding if the model
# artifact is missing — which would make the classifier look perfectly
# recalled and useless, so say so rather than silently reporting it.
score_findings(reviewed)
if all(d.get("p_real") == 1.0 for d in reviewed):
    print("WARNING: every finding scored exactly 1.0, which is score_findings()'s\n"
          "         no-model fallback. model/risk_classifier.pkl is probably missing —\n"
          "         run train_classifier.py first. Numbers below are meaningless.\n")

y_true = [1 if d["human_label"] == "real" else 0 for d in reviewed]
y_pred = [1 if (d.get("p_real") or 0) >= REAL_THRESHOLD else 0 for d in reviewed]

# The stored confidence is what the model said when the sample was built. If
# it has drifted from the live score, the model has been retrained since —
# worth surfacing, since it's the difference between the figures quoted in
# NOTES.md/PRODUCT.md and what this run reports.
stale = [d for d in reviewed
         if d.get("confidence") is not None
         and abs(d["confidence"] - (d.get("p_real") or 0)) > 0.01]
if stale:
    old_pred = [1 if (d["confidence"] or 0) >= REAL_THRESHOLD else 0 for d in reviewed]
    old_tp = sum(1 for a, b in zip(y_true, old_pred) if a == 1 and b == 1)
    new_tp = sum(1 for a, b in zip(y_true, y_pred) if a == 1 and b == 1)
    print(f"Note: {len(stale)}/{len(reviewed)} findings score differently now than when\n"
          f"      the sample was built — the model has been retrained since. Real\n"
          f"      findings correctly caught: {old_tp} then, {new_tp} now.\n"
          f"      Figures below are the CURRENT model.\n")

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
    yp = [1 if (d.get("p_real") or 0) >= REAL_THRESHOLD else 0 for d in subset]
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
