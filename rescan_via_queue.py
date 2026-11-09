"""
Rescans every repository already in the database, through the scan queue,
one at a time, and records each repo's results before and after.

Why not batch_scan.py: that calls scan_repo() in its own process. On the VPS
the worker is already running, so a visitor submitting a scan meanwhile
would put two scans side by side on a 4GB host (Semgrep alone peaks near
2GB). This script only ever *queues* a scan, and only when the queue is
empty, so the worker stays the single consumer: a visitor's scan waits
behind at most one of these, and the next one waits for the visitor's.

Written for 2026-11-09, when every stored result predated hidden-payload
decoding, UTF-16 reading, the reference-file guard, IOC extraction and
ClamAV 1.4.6. The before/after records are what the report's numbers on
those changes come from.

Skips repositories whose source_status is "gone" (deleted from GitHub; the
scan could only fail) or "renamed" (the original row of a renamed repo;
its successor is scanned under its new name), and anything at or over the
size limit the scan form enforces.

Run inside the app container on the VPS, detached so it survives SSH:

    docker cp rescan_via_queue.py maldet-app-1:/app/
    docker compose exec -d app python3 rescan_via_queue.py --out /app/rescan-run
    docker compose exec app tail -f /app/rescan-run/progress.log

    --limit N    stop after N repos       --resume   skip repos already recorded
    --only a/b   just these (repeatable)
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime

import pymysql
import requests

import job_queue
from db_connect import connect
from scanner import HEADERS

MAX_MB = int(os.environ.get("MALDET_REPO_MAX_MB", "5000"))
JOB_TIMEOUT_S = 2 * 3600       # a scan has never taken an hour; past two, move on
POLL_S = 10


def db():
    return connect(cursorclass=pymysql.cursors.DictCursor)


def targets(only):
    with db() as conn, conn.cursor() as cur:
        cur.execute("""SELECT id, owner, repo_name, source_status FROM repositories
                       ORDER BY id""")
        rows = cur.fetchall()
    if only:
        wanted = {o.lower() for o in only}
        rows = [r for r in rows if f"{r['owner']}/{r['repo_name']}".lower() in wanted]
    return rows


def snapshot(repo_id):
    """What a repo's stored result says right now, for the before/after."""
    with db() as conn, conn.cursor() as cur:
        cur.execute("""SELECT vuln_level, vuln_score, malware_level, malware_score
                       FROM risk_scores WHERE repo_id=%s""", (repo_id,))
        risk = cur.fetchone() or {}
        cur.execute("""SELECT tool, severity, COUNT(*) n FROM scan_results
                       WHERE repo_id=%s GROUP BY tool, severity""", (repo_id,))
        by_tool = {}
        for r in cur.fetchall():
            by_tool.setdefault(r["tool"], {})[r["severity"]] = r["n"]
        cur.execute("""SELECT
                         SUM(issue_text LIKE 'Hidden payload:%%')   AS hidden,
                         SUM(issue_text LIKE 'Reference in a %%')   AS reference,
                         COUNT(DISTINCT CASE WHEN tool IN ('yara','clamav') THEN filename END)
                                                                    AS malware_files
                       FROM scan_results WHERE repo_id=%s""", (repo_id,))
        extra = cur.fetchone() or {}
        cur.execute("""SELECT COUNT(*) n FROM iocs i JOIN scan_history h ON h.id = i.scan_id
                       WHERE h.repo_id=%s AND h.id = (SELECT MAX(id) FROM scan_history
                                                      WHERE repo_id=%s)""", (repo_id, repo_id))
        iocs = cur.fetchone()["n"]
    risk = {k: (float(v) if isinstance(v, (int, float)) or hasattr(v, "is_finite") else v)
            for k, v in risk.items()}
    return {**risk, "by_tool": by_tool, "hidden": int(extra.get("hidden") or 0),
            "reference": int(extra.get("reference") or 0),
            "malware_files": int(extra.get("malware_files") or 0), "iocs": iocs}


def size_mb(slug):
    try:
        resp = requests.get(f"https://api.github.com/repos/{slug}", headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            return round(resp.json().get("size", 0) / 1024)
    except requests.RequestException:
        pass
    return None


def queue_busy():
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) n FROM scan_jobs WHERE status IN ('queued','running')")
        return cur.fetchone()["n"] > 0


def wait_for(job_id):
    start = time.monotonic()
    while time.monotonic() - start < JOB_TIMEOUT_S:
        job = job_queue.get_job(job_id)
        if job and job["status"] in ("done", "error"):
            return job
        time.sleep(POLL_S)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="rescan-run")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--only", action="append")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    results_path = os.path.join(args.out, "results.jsonl")
    log_path = os.path.join(args.out, "progress.log")
    done = set()
    if args.resume and os.path.exists(results_path):
        done = {json.loads(l)["repo"] for l in open(results_path)}

    def log(msg):
        line = f"{datetime.now():%Y-%m-%d %H:%M:%S} {msg}"
        print(line, flush=True)
        with open(log_path, "a") as fh:
            fh.write(line + "\n")

    rows = [r for r in targets(args.only) if f"{r['owner']}/{r['repo_name']}" not in done]
    log(f"{len(rows)} repositories to consider")
    scanned = 0
    for i, row in enumerate(rows, 1):
        if args.limit and scanned >= args.limit:
            break
        slug = f"{row['owner']}/{row['repo_name']}"
        record = {"repo": slug, "repo_id": row["id"]}
        if row["source_status"] in ("gone", "renamed"):
            record["status"] = f"skipped ({row['source_status']})"
        else:
            mb = size_mb(slug)
            record["size_mb"] = mb
            if mb is not None and mb >= MAX_MB:
                record["status"] = f"skipped (over {MAX_MB} MB)"
        if "status" in record:
            log(f"[{i}/{len(rows)}] {slug}: {record['status']}")
        else:
            while queue_busy():          # never more than one scan in the queue
                time.sleep(15)
            record["before"] = snapshot(row["id"])
            started = time.monotonic()
            job_id = job_queue.enqueue(slug, "infected")
            log(f"[{i}/{len(rows)}] {slug}: queued ({record['size_mb']} MB)")
            job = wait_for(job_id)
            record["seconds"] = round(time.monotonic() - started)
            if job is None:
                record["status"] = "timed out waiting"
            elif job["status"] == "error":
                record["status"] = "failed"
                record["error"] = (job.get("error") or "")[:300]
            else:
                record["status"] = "done"
                record["after"] = snapshot(job["repo_id"] or row["id"])
            scanned += 1
            b, a = record["before"], record.get("after", {})
            log(f"[{i}/{len(rows)}] {slug}: {record['status']} in {record['seconds']}s"
                + (f"; malware {b.get('malware_level')} -> {a.get('malware_level')}, "
                   f"hidden {a.get('hidden')}, reference {a.get('reference')}, "
                   f"iocs {a.get('iocs')}" if a else ""))
        with open(results_path, "a") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
    log("finished")


if __name__ == "__main__":
    sys.exit(main())
