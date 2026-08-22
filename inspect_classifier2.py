import joblib
import pandas as pd
from train_classifier import load_findings, build_features, MODEL_PATH

pd.set_option("display.max_colwidth", 70)
pd.set_option("display.width", 160)

SEVERITY_WEIGHT = {"high": 10, "medium": 3, "low": 1}

pipeline = joblib.load(MODEL_PATH)
df = load_findings()
df, total_repos = build_features(df)
X = df[["tool", "severity_norm", "repo_frequency", "snippet_length", "issue_text"]]
df["p_real"] = pipeline.predict_proba(X)[:, 1]
df["weight"] = df["severity_norm"].map(SEVERITY_WEIGHT).fillna(1)
df["weighted_contribution"] = df["weight"] * df["p_real"]

print("=" * 78)
print("Old (raw count) score vs. a probability-weighted score, across several")
print("repos from your dashboard — old_score just sums severity weights,")
print("new_score sums severity_weight x P(real). No capping applied here,")
print("this is purely to show the effect of the classifier, not the final formula.")
print("=" * 78)

repo_names = pd.read_sql if False else None  # placeholder, using raw query below
import pymysql
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME
conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME,
                        cursorclass=pymysql.cursors.DictCursor)
with conn.cursor() as cur:
    cur.execute("SELECT id, repo_name, owner FROM repositories")
    repo_lookup = {r["id"]: f"{r['owner']}/{r['repo_name']}" for r in cur.fetchall()}
conn.close()

summary = (
    df.groupby("repo_id")
    .agg(
        n_findings=("weight", "size"),
        old_score=("weight", "sum"),
        new_score=("weighted_contribution", "sum"),
    )
)
summary["repo"] = summary.index.map(repo_lookup)
summary["reduction_pct"] = (1 - summary["new_score"] / summary["old_score"]) * 100
summary = summary.sort_values("old_score", ascending=False)

print(summary[["repo", "n_findings", "old_score", "new_score", "reduction_pct"]].head(15).to_string())

print()
print("=" * 78)
print("ClamAV findings (actual antivirus signature matches) — sanity check")
print("that these stay high-confidence real, since they're hardcoded as such")
print("=" * 78)
clamav = df[df["tool"] == "clamav"]
print(f"Total ClamAV findings in the corpus: {len(clamav)}")
if len(clamav) > 0:
    print(clamav[["repo_id", "issue_text", "p_real"]].head(10).to_string(index=False))

print()
print("=" * 78)
print("dep_checker findings (typosquat / CVE / suspicious install patterns) —")
print("how confident is the model about these, spread across the corpus?")
print("=" * 78)
dep = df[df["tool"] == "dep_checker"]
print(f"Total dep_checker findings: {len(dep)}")
print(dep.groupby("issue_text_short" if "issue_text_short" in dep.columns else dep["issue_text"].str.slice(0, 60))["p_real"]
      .agg(["mean", "count"]).sort_values("mean", ascending=False).head(10).to_string())
