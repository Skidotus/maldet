import joblib
import pandas as pd
from train_classifier import load_findings, build_features, MODEL_PATH
from scanner import NOISE_RULES

pd.set_option("display.max_colwidth", 70)
pd.set_option("display.width", 140)

pipeline = joblib.load(MODEL_PATH)
df = load_findings()
df, total_repos = build_features(df)

X = df[["tool", "severity_norm", "repo_frequency", "snippet_length", "issue_text"]]
df["p_real"] = pipeline.predict_proba(X)[:, 1]
df["issue_text_short"] = df["issue_text"].str.slice(0, 65)

print("=" * 70)
print("mlflow (repo_id=9) — its 39 'high' severity findings, ranked by the")
print("model's confidence they're a REAL finding (not noise)")
print("=" * 70)
mlflow_high = df[(df["repo_id"] == 9) & (df["severity_norm"] == "high")]
print(mlflow_high[["tool", "issue_text_short", "repo_frequency", "p_real"]]
      .sort_values("p_real")
      .to_string(index=False))

print()
print("=" * 70)
print("Ambiguous findings (not caught by hardcoded NOISE_RULES or IGNORE_PATHS,")
print("not extreme enough on frequency to be an auto-label either way) that")
print("the model is now MOST confident are noise")
print("=" * 70)
ambiguous = df[
    (~df["issue_text"].isin(NOISE_RULES))
    & (df["repo_frequency"] < 0.20)
    & (df["repo_frequency"] > 0.02)
]
top_noise_calls = (
    ambiguous.groupby(["tool", "issue_text_short"])
    .agg(p_real=("p_real", "mean"), repo_frequency=("repo_frequency", "first"), n=("p_real", "size"))
    .sort_values("p_real")
    .head(10)
)
print(top_noise_calls.to_string())

print()
print("=" * 70)
print("Same ambiguous pool — findings the model is MOST confident are real")
print("=" * 70)
top_real_calls = (
    ambiguous.groupby(["tool", "issue_text_short"])
    .agg(p_real=("p_real", "mean"), repo_frequency=("repo_frequency", "first"), n=("p_real", "size"))
    .sort_values("p_real", ascending=False)
    .head(10)
)
print(top_real_calls.to_string())
