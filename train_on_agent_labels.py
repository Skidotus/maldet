"""
Experiment: train the classifier on labels made by reading the code
(train_labels.jsonl, written by an LLM agent) instead of the weak labels
train_classifier.py derives from rule frequency, and compare the result with
the shipped model on the held-out eval_sample.json.

It never touches model/risk_classifier.pkl. The candidate is saved beside it
as model/candidate_agent_labels.pkl, and replacing the shipped model is a
separate, deliberate step.

Three numbers, in order of how much they can be trusted:
  1. shipped vs candidate on eval_sample.json, which neither trained on
  2. the same, restricted to eval findings whose rule the candidate never
     saw in training (the harder, fairer case)
  3. cross-validation on the agent labels with whole repositories held out

The labels on both sides were made by AI models, not by a person, so these
figures say the candidate agrees better with a careful reading of the code,
not that it is right. A blind human check of a sample is what settles that.

    python3 train_on_agent_labels.py
"""

import json
import os

import joblib
import numpy as np
import pandas as pd
import pymysql
from sklearn.base import clone
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import GroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

import scanner
from db_connect import connect
from scanner import FEATURE_COLUMNS, frequency_key
from train_classifier import build_features

SAMPLE, LABELS, EVAL = "train_sample.json", "train_labels.jsonl", "eval_sample.json"
CANDIDATE_PATH = os.path.join(os.path.dirname(__file__), "model", "candidate_agent_labels.pkl")
THRESHOLD = 0.5


def make_pipeline():
    features = ColumnTransformer([
        ("tool_ohe",     OneHotEncoder(handle_unknown="ignore"), ["tool"]),
        ("severity_ohe", OneHotEncoder(handle_unknown="ignore"), ["severity_norm"]),
        ("conf_ohe",     OneHotEncoder(handle_unknown="ignore"), ["tool_confidence"]),
        ("text_tfidf",   TfidfVectorizer(max_features=300, stop_words="english"), "issue_text"),
    ], remainder="passthrough")
    return Pipeline([
        ("features", features),
        ("model", RandomForestClassifier(n_estimators=200, max_depth=12,
                                         class_weight="balanced", random_state=42, n_jobs=-1)),
    ])


def load_corpus():
    db = connect()
    try:
        cur = db.cursor(pymysql.cursors.DictCursor)
        cur.execute("""SELECT COUNT(*) AS n FROM information_schema.COLUMNS
                       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scan_results'
                         AND COLUMN_NAME = 'tool_confidence'""")
        conf = ", tool_confidence" if cur.fetchone()["n"] else ""
        cur.execute(f"""SELECT id, repo_id, tool, severity, issue_text, filename,
                               line_number, code_snippet{conf} FROM scan_results""")
        return pd.DataFrame(cur.fetchall())
    finally:
        db.close()


def report(name, y_true, p):
    pred = [1 if x >= THRESHOLD else 0 for x in p]
    prec, rec, f1, _ = precision_recall_fscore_support(y_true, pred, average="binary",
                                                       zero_division=0)
    auc = roc_auc_score(y_true, p) if len(set(y_true)) == 2 else float("nan")
    acc = sum(a == b for a, b in zip(y_true, pred)) / len(y_true)
    print(f"  {name:<22} n={len(y_true):>3}  AUC {auc:.3f}  accuracy {acc:.3f}  "
          f"real: precision {prec:.3f} recall {rec:.3f} F1 {f1:.3f}")


def score_eval(artifact, contexts, samples):
    """p_real for each eval sample through scanner.score_findings(), the code
    a real scan uses, with each sample scored among its repo's findings."""
    scanner._model_artifact = artifact
    p = {}
    for rows in contexts.values():
        rows = [dict(r) for r in rows]
        scanner.score_findings(rows)
        p.update({r["id"]: r["p_real"] for r in rows})
    return [p[d["id"]] for d in samples]


def main():
    with open(SAMPLE) as fh:
        sample = {x["id"]: x for x in json.load(fh)}
    with open(LABELS) as fh:
        labels = {r["id"]: r["label"] for r in map(json.loads, filter(str.strip, fh))}
    with open(EVAL) as fh:
        eval_rows = [d for d in json.load(fh) if d.get("human_label")]

    df, total_repos = build_features(load_corpus())
    train = df[df["id"].isin(labels)].copy()
    train["label"] = [1 if labels[i] == "real" else 0 for i in train["id"]]
    missing = len(labels) - len(train)
    print(f"{len(train)} labelled findings ({int(train['label'].sum())} real) from "
          f"{train['repo_id'].nunique()} repos"
          + (f"; {missing} no longer in the database" if missing else ""))

    # 3. Cross-validation with whole repositories held out.
    X, y, groups = train[FEATURE_COLUMNS], train["label"].to_numpy(), train["repo_id"]
    oof = np.zeros(len(train))
    for tr, te in GroupKFold(n_splits=5).split(X, y, groups):
        fold = clone(make_pipeline()).fit(X.iloc[tr], y[tr])
        oof[te] = fold.predict_proba(X.iloc[te])[:, 1]

    pipeline = make_pipeline().fit(X, y)
    freq_lookup = df.groupby(["tool", "frequency_key"])["repo_frequency"].first().to_dict()
    candidate = {
        "pipeline": pipeline,
        "frequency_lookup": freq_lookup,
        "default_frequency": float(np.median(list(freq_lookup.values()))),
        "total_repos": total_repos,
        "feature_cols": list(FEATURE_COLUMNS),
        "labels": "LLM agent labels (train_labels.jsonl), not human-reviewed",
    }
    joblib.dump(candidate, CANDIDATE_PATH)
    shipped = joblib.load(scanner.MODEL_ARTIFACT_PATH)

    # Each eval sample is scored among its repo's stored findings, as
    # evaluate_classifier.py does, so the tool-agreement features are real.
    by_repo = {rid: g.to_dict("records") for rid, g in
               df[df["repo_id"].isin({d["repo_id"] for d in eval_rows})]
               [["id", "repo_id", "tool", "severity", "issue_text", "filename",
                 "line_number", "code_snippet", "tool_confidence"]].groupby("repo_id")}
    contexts = {}
    for d in eval_rows:
        rows = contexts.setdefault(d["repo_id"], list(by_repo.get(d["repo_id"], [])))
        if d["id"] not in {r["id"] for r in rows}:
            rows.append({k: d.get(k) for k in ("id", "repo_id", "tool", "severity", "issue_text",
                                               "filename", "line_number", "code_snippet")})

    y_eval = [1 if d["human_label"] == "real" else 0 for d in eval_rows]
    p_ship = score_eval(shipped, contexts, eval_rows)
    p_cand = score_eval(candidate, contexts, eval_rows)

    seen = {(t, frequency_key(t, txt)) for t, txt in zip(train["tool"], train["issue_text"])}
    unseen = [i for i, d in enumerate(eval_rows)
              if (d["tool"], frequency_key(d["tool"], d["issue_text"])) not in seen]

    print(f"\n1. Held-out evaluation set ({EVAL})")
    report("shipped model", y_eval, p_ship)
    report("candidate", y_eval, p_cand)
    print(f"\n2. Only eval findings whose rule the candidate never trained on")
    report("shipped model", [y_eval[i] for i in unseen], [p_ship[i] for i in unseen])
    report("candidate", [y_eval[i] for i in unseen], [p_cand[i] for i in unseen])
    print("\n3. Agent labels, five folds with whole repositories held out")
    report("candidate (out of fold)", list(y), list(oof))

    print("\nPer engine on the evaluation set (correct at 0.5): shipped / candidate")
    for tool in sorted({d["tool"] for d in eval_rows}):
        idx = [i for i, d in enumerate(eval_rows) if d["tool"] == tool]
        hit = lambda p: sum((p[i] >= THRESHOLD) == bool(y_eval[i]) for i in idx)
        print(f"  {tool:<12} n={len(idx):>3}  {hit(p_ship):>3} / {hit(p_cand):>3}")
    print(f"\nCandidate saved to {CANDIDATE_PATH}; the shipped model is unchanged.")


if __name__ == "__main__":
    main()
