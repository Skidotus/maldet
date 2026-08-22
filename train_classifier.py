"""
Trains a Random Forest to score each finding with P(real issue), instead of
counting every finding equally in calculate_risk().

There's no hand-labeled ground truth (no one has marked individual findings
as real-issue-vs-noise), so this bootstraps weak labels from two signals
that are already implicit in the data:
  - the existing NOISE_RULES / IGNORE_PATHS heuristics in scanner.py
  - how many different repos a given (tool, issue_text) shows up in — a
    rule that fires across a huge fraction of unrelated repos is almost
    certainly boilerplate, not a specific finding about this repo

Only confidently-labeled findings are used for training/evaluation; the
ambiguous middle is left out of training but still scored at inference
time. Run standalone: `python3 train_classifier.py`.
"""

import os
import joblib
import numpy as np
import pandas as pd
import pymysql
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME
from scanner import NOISE_RULES, IGNORE_PATHS, normalize_severity, frequency_key

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model", "risk_classifier.pkl")

# A rule firing across more than this fraction of all scanned repos is
# treated as boilerplate regardless of what NOISE_RULES says explicitly —
# generalizes the hand-curated list instead of just replicating it.
HIGH_FREQUENCY_THRESHOLD = 0.20
# A rule that's genuinely rare (seen in only a sliver of repos) is treated
# as a confident "real finding" signal, unless it's already known noise.
LOW_FREQUENCY_THRESHOLD = 0.02


def load_findings():
    conn = pymysql.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor
    )
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT repo_id, tool, severity, issue_text, filename, code_snippet
                FROM scan_results
            """)
            rows = cur.fetchall()
    finally:
        conn.close()
    return pd.DataFrame(rows)


def build_features(df):
    df["severity_norm"] = df["severity"].fillna("low").apply(normalize_severity)
    df["filename"] = df["filename"].fillna("")
    df["issue_text"] = df["issue_text"].fillna("")
    df["code_snippet"] = df["code_snippet"].fillna("")

    df["is_ignored_path"] = df["filename"].str.lower().apply(
        lambda f: any(p in f for p in IGNORE_PATHS)
    )
    df["is_known_noise_text"] = df["issue_text"].isin(NOISE_RULES)
    df["snippet_length"] = df["code_snippet"].str.len()
    df["frequency_key"] = df.apply(
        lambda r: frequency_key(r["tool"], r["issue_text"]), axis=1
    )

    total_repos = df["repo_id"].nunique()
    freq = (
        df.groupby(["tool", "frequency_key"])["repo_id"]
        .nunique()
        .div(total_repos)
        .rename("repo_frequency")
    )
    df = df.join(freq, on=["tool", "frequency_key"])
    return df, total_repos


def weak_label(df):
    """1 = confidently a real finding, 0 = confidently noise, NaN = ambiguous
    (excluded from training, still scored at inference time)."""
    is_confident_noise = (
        df["is_known_noise_text"]
        | df["is_ignored_path"]
        | (df["repo_frequency"] >= HIGH_FREQUENCY_THRESHOLD)
    )

    # Deliberately NOT special-casing "yara severity=high" as auto-trusted
    # here, despite that seeming reasonable on paper — checked it against
    # real data first. Several "composite" high-severity rules turned out
    # far more common in real code than intended (detect_download_and_execute
    # fires in 53% of repos, detect_persistence_mechanism in 42%,
    # detect_base64_exec in 21% — mostly CI scripts, dotfile docs, and
    # legitimate encode/decode code, not malice). Only detect_reverse_shell
    # and detect_clipboard_hijack turned out genuinely rare (~1%), and they
    # clear LOW_FREQUENCY_THRESHOLD on their own merit below — no rule
    # deserves blanket trust just for being "high" severity by design intent;
    # let the observed frequency decide, same as every other tool.
    is_confident_signal = (
        (~df["is_known_noise_text"])
        & (~df["is_ignored_path"])
        & (
            (df["tool"] == "clamav")
            | (df["repo_frequency"] <= LOW_FREQUENCY_THRESHOLD)
        )
    )

    label = pd.Series(np.nan, index=df.index)
    label[is_confident_noise] = 0
    label[is_confident_signal] = 1
    # a row can't be both — noise rules win if they somehow overlap
    label[is_confident_noise] = 0
    return label


def main():
    print("Loading findings from the database...")
    df = load_findings()
    print(f"  {len(df):,} findings loaded")

    df, total_repos = build_features(df)
    print(f"  spanning {total_repos} repos")

    df["label"] = weak_label(df)
    labeled = df.dropna(subset=["label"]).copy()
    labeled["label"] = labeled["label"].astype(int)

    n_noise  = (labeled["label"] == 0).sum()
    n_signal = (labeled["label"] == 1).sum()
    n_ambiguous = len(df) - len(labeled)
    print(f"\nWeak labels:")
    print(f"  {n_noise:,} confidently noise")
    print(f"  {n_signal:,} confidently real findings")
    print(f"  {n_ambiguous:,} ambiguous (left out of training)")

    feature_cols = ["tool", "severity_norm", "repo_frequency", "snippet_length", "issue_text"]
    X = labeled[feature_cols]
    y = labeled["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    preprocessor = ColumnTransformer([
        ("tool_ohe",     OneHotEncoder(handle_unknown="ignore"), ["tool"]),
        ("severity_ohe", OneHotEncoder(handle_unknown="ignore"), ["severity_norm"]),
        ("text_tfidf",   TfidfVectorizer(max_features=300, stop_words="english"), "issue_text"),
    ], remainder="passthrough")  # repo_frequency, snippet_length pass through as-is

    pipeline = Pipeline([
        ("features", preprocessor),
        ("model", RandomForestClassifier(
            n_estimators=200, max_depth=12, class_weight="balanced",
            random_state=42, n_jobs=-1
        )),
    ])

    print("\nTraining...")
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    print("\nEvaluation on held-out weak-labeled test set:")
    print(classification_report(y_test, y_pred, target_names=["noise", "real finding"]))
    print("Confusion matrix (rows=actual, cols=predicted) [noise, real]:")
    print(confusion_matrix(y_test, y_pred))

    # A live scan sees findings whose exact (tool, frequency_key) never
    # appeared in this training corpus — there's no way to know if a brand
    # new finding type is rare or common. default_frequency uses the median
    # across distinct finding TYPES (not individual findings) as the
    # fallback: the per-finding median is skewed high (~0.28) by a handful
    # of extremely repetitive boilerplate rules, whereas most distinct rule
    # types are actually narrow/specific (median ~0.007). Defaulting new,
    # unseen findings toward "rare" errs on the side of caution — a
    # reasonable posture for a security tool encountering something novel.
    freq_lookup = (
        df.groupby(["tool", "frequency_key"])["repo_frequency"]
        .first()
        .to_dict()
    )
    default_frequency = float(np.median(list(freq_lookup.values())))

    artifact = {
        "pipeline": pipeline,
        "frequency_lookup": freq_lookup,
        "default_frequency": default_frequency,
        "total_repos": total_repos,
    }

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(artifact, MODEL_PATH)
    print(f"\nSaved model + frequency lookup ({len(freq_lookup):,} entries, "
          f"default={default_frequency:.4f}) to {MODEL_PATH}")

    return pipeline, df


if __name__ == "__main__":
    main()
