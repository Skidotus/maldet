"""
Runs the full scan pipeline over many repositories unattended — an overnight
job, since a single repo takes anywhere from 30 seconds to several minutes.

Two uses, both of which need the *whole* pipeline rather than a partial
rescan:

  1. Adding repos, to give train_classifier.py more to learn from. The weak
     labels there come from how rare a (tool, issue_text) pair is across the
     corpus, so the corpus *is* the training dataset — scanning more repos is
     how you extend it. Worth knowing: as of writing only 12 of 156 repos
     carry meaningful malicious patterns, so the classifier has seen very
     little of what it exists to catch.

  2. Re-scanning repos already in the database (--existing), to recover the
     findings the IGNORE_PATHS substring bug discarded between 2026-07-31 and
     932acd6. That loss is in Bandit/Semgrep output, so rescan_yara_dep.py
     can't repair it — only a full rescan can.

Usage:
    python3 batch_scan.py repos.txt              # scan the repos listed
    python3 batch_scan.py repos.txt --new-only   # skip any already in the DB
    python3 batch_scan.py --existing             # rescan everything in the DB
    python3 batch_scan.py repos.txt --limit 20   # stop after 20
    python3 batch_scan.py repos.txt --resume     # skip repos already done

The input file takes one repo per line, in any form scan_repo() accepts
(`owner/repo`, `github.com/owner/repo`, or a full URL). Blank lines and
lines starting with # are ignored.

A repo that fails is recorded and skipped — the run carries on, because
losing an eight-hour batch to one dead URL is not acceptable. Every outcome
is appended to batch_scan.log, which is also what --resume reads.

One caution when adding malicious repos: repo_frequency is measured against
this corpus, so if malicious patterns stop being rare the weak labeller will
start classifying them as boilerplate noise. Adding 20-40 on top of the
current ~156 is the intended scale; adding hundreds would make the model
worse, not better.

After a run finishes:
    python3 train_classifier.py      # retrain on the enlarged corpus
    python3 evaluate_classifier.py   # score against the same held-out set
"""

import os
import sys
import time
import traceback
from datetime import datetime

import pymysql

from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME
from scanner import scan_repo

LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "batch_scan.log")

args     = [a for a in sys.argv[1:] if not a.startswith("--")]
flags    = [a for a in sys.argv[1:] if a.startswith("--")]
EXISTING = "--existing" in flags
NEW_ONLY = "--new-only" in flags
RESUME   = "--resume" in flags

LIMIT = None
for f in flags:
    if f.startswith("--limit"):
        # accepts --limit=20; bare --limit takes the next positional
        if "=" in f:
            LIMIT = int(f.split("=", 1)[1])
        elif args:
            LIMIT = int(args.pop())


def db():
    return pymysql.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor
    )


def normalize(line):
    """`owner/repo` out of any of the forms scan_repo() accepts."""
    s = line.strip()
    s = s.replace("https://", "").replace("http://", "")
    s = s.replace("github.com/", "").strip("/")
    if s.endswith(".git"):
        s = s[:-4]
    parts = s.split("/")
    return f"{parts[0]}/{parts[1]}" if len(parts) >= 2 else None


def targets_from_file(path):
    if not os.path.exists(path):
        sys.exit(f"No such file: {path}")

    out, bad = [], []
    with open(path) as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            repo = normalize(line)
            (out if repo else bad).append(repo or line)

    if bad:
        print(f"Skipping {len(bad)} unparseable line(s): {', '.join(bad[:5])}"
              + (" ..." if len(bad) > 5 else ""))

    # de-duplicate, keeping file order
    seen, unique = set(), []
    for r in out:
        if r not in seen:
            seen.add(r)
            unique.append(r)
    return unique


def targets_from_db():
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT owner, repo_name FROM repositories ORDER BY id")
            return [f"{r['owner']}/{r['repo_name']}" for r in cur.fetchall()]
    finally:
        conn.close()


def already_in_db():
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT owner, repo_name FROM repositories")
            return {f"{r['owner']}/{r['repo_name']}" for r in cur.fetchall()}
    finally:
        conn.close()


def already_done():
    """Repos logged as OK by an earlier run, for --resume."""
    if not os.path.exists(LOG_PATH):
        return set()
    done = set()
    with open(LOG_PATH) as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 3 and parts[1] == "OK":
                done.add(parts[2])
    return done


def log(status, repo, detail=""):
    with open(LOG_PATH, "a") as fh:
        fh.write(f"{datetime.now().isoformat(timespec='seconds')}\t{status}\t{repo}\t{detail}\n")


def human(seconds):
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    return f"{h}h {m:02d}m" if h else f"{m}m {s:02d}s"


def main():
    if EXISTING:
        repos = targets_from_db()
        print(f"Re-scanning {len(repos)} repositories already in the database.")
    elif args:
        repos = targets_from_file(args[0])
        print(f"Read {len(repos)} repositories from {args[0]}.")
    else:
        sys.exit(__doc__.strip().split("\n\n")[0] +
                 "\n\nUsage: python3 batch_scan.py repos.txt [--new-only] "
                 "[--resume] [--limit=N]\n       python3 batch_scan.py --existing")

    if NEW_ONLY:
        known = already_in_db()
        before = len(repos)
        repos = [r for r in repos if r not in known]
        print(f"--new-only: skipped {before - len(repos)} already in the database.")

    if RESUME:
        done = already_done()
        before = len(repos)
        repos = [r for r in repos if r not in done]
        print(f"--resume: skipped {before - len(repos)} completed in an earlier run.")

    if LIMIT:
        repos = repos[:LIMIT]
        print(f"--limit: stopping after {len(repos)}.")

    if not repos:
        print("Nothing to scan.")
        return

    print(f"\nScanning {len(repos)} repositories. Logging to {LOG_PATH}")
    print("Safe to leave running; Ctrl-C stops after the current repo.\n")

    t0 = time.time()
    ok = failed = 0
    failures = []

    for i, repo in enumerate(repos, 1):
        elapsed = time.time() - t0
        eta = ""
        if i > 1:
            per = elapsed / (i - 1)
            eta = f" · ~{human(per * (len(repos) - i + 1))} left"
        print(f"\n[{i}/{len(repos)}] {repo}{eta}", flush=True)

        started = time.time()
        try:
            result = scan_repo(repo)
            took = time.time() - started
            ok += 1
            # scan_repo() returns the full result dict, not just an id.
            summary = (f"{result['risk_level']} · "
                       f"{result['high']}H/{result['medium']}M/{result['low']}L")
            print(f"  done in {human(took)} — {summary}", flush=True)
            log("OK", repo, f"repo_id={result['repo_id']} score={result['score']} "
                            f"level={result['risk_level']} took={int(took)}s")

        except KeyboardInterrupt:
            print("\nInterrupted — stopping. Re-run with --resume to continue.")
            log("INTERRUPTED", repo)
            break

        except Exception as e:
            failed += 1
            failures.append((repo, str(e)))
            # One bad repo must not end an overnight run.
            print(f"  FAILED: {type(e).__name__}: {e}", flush=True)
            log("FAIL", repo, f"{type(e).__name__}: {e}")
            traceback.print_exc(file=sys.stdout)

    total = time.time() - t0
    print(f"\n{'='*50}")
    print(f"Scanned {ok} ok, {failed} failed, in {human(total)}")
    if failures:
        print("\nFailures:")
        for repo, err in failures:
            print(f"  {repo}: {err}")
        print("\nRe-run with --resume to retry only these.")
    print(f"\nNext: python3 train_classifier.py && python3 evaluate_classifier.py")


if __name__ == "__main__":
    main()
