"""
Scan worker -- the only process that runs scans.

Run exactly one of these alongside the web app:

    python3 worker.py

The web app only ever writes rows to `scan_jobs`; everything expensive
happens here. Keeping it a separate process is what makes the deployment
safe on a small VPS: the web side can be given several workers for
responsiveness without multiplying the scanners, and a scan that crashes
the interpreter takes down the worker rather than the site.

Running two of these at once is not fatal -- job_queue.claim_next() holds a
row lock and refuses to claim while another job is running -- but it is
pointless, since the second would simply idle.
"""

import os
import sys
import time
import signal

import pymysql

import job_queue
import llm_summary
from backfill_summaries import repo_for_summary, summarize_one
from db_connect import connect
from scanner import scan_repo

# How long to wait before looking for work again. Two seconds is responsive
# enough for a web form and costs one trivial indexed query per tick.
POLL_SECONDS = float(os.environ.get("MALDET_WORKER_POLL", "2"))

_stop = False


def _handle_stop(signum, frame):
    """Finish the scan in progress, then exit -- rather than orphaning it.

    A killed mid-scan job would be left 'running' and block the queue until
    the next restart's recover_stale(), so the polite path is to stop taking
    new work and let the current one finish.
    """
    global _stop
    _stop = True
    print("\n[worker] stop requested; finishing current scan then exiting", flush=True)


def _write_summary(repo_id, repo_label, label):
    """Generate this repo's plain-English summary, after the scan is done.

    Never raises: a scan that completed must stay completed even if the
    explainer falls over, so every failure is recorded as "unavailable" and
    the detail page falls back to the rule-based text.
    """
    if not llm_summary.is_available():
        print(f"[{label}] no summary for {repo_label}: Ollama unavailable", flush=True)
        _mark_unavailable(repo_id)
        return
    started = time.time()
    try:
        db = connect(autocommit=True)
        try:
            cur = db.cursor(pymysql.cursors.DictCursor)
            repo = repo_for_summary(cur, repo_id)
            if not repo:
                return
            text = summarize_one(cur, repo)
        finally:
            db.close()
    except Exception as e:
        print(f"[{label}] summary failed for {repo_label}: {type(e).__name__}: {e}", flush=True)
        _mark_unavailable(repo_id)
        return
    took = time.time() - started
    if text:
        print(f"[{label}] summarised {repo_label} in {took:.0f}s", flush=True)
    else:
        print(f"[{label}] no summary for {repo_label} ({took:.0f}s)", flush=True)


def _mark_unavailable(repo_id):
    """Stop the detail page waiting for a summary that is not coming."""
    try:
        db = connect(autocommit=True)
        try:
            db.cursor().execute("""UPDATE risk_scores SET llm_summary_status = 'unavailable'
                                   WHERE repo_id = %s AND llm_summary_status = 'pending'""",
                                (repo_id,))
        finally:
            db.close()
    except Exception:
        # Best effort. A row stuck on "pending" is cleaned up at the next
        # worker start, and the page gives up waiting on its own.
        pass


def _clear_stale_summaries():
    """Release summaries left "pending" by a worker that died mid-generation.

    Same reasoning as job_queue.recover_stale(): only one worker runs, so a
    "pending" row at startup is always orphaned, and left alone it spins the
    detail page forever.
    """
    try:
        db = connect(autocommit=True)
        try:
            cur = db.cursor()
            cur.execute("""UPDATE risk_scores SET llm_summary_status = 'unavailable'
                           WHERE llm_summary_status = 'pending'""")
            return cur.rowcount
        finally:
            db.close()
    except Exception as e:
        print(f"[worker] could not clear stale summaries ({type(e).__name__})", flush=True)
        return 0


def run_forever(recover=True, label="worker"):
    """Consume the queue until stopped. Safe to call from a thread.

    Split out of main() so app.py can run it inline for local development
    (one command instead of two terminals). Signal handling stays in main()
    because signal.signal() only works on the main thread.

    `recover` is False for the inline worker: recover_stale() fails every job
    marked running, which is correct at the start of the one true worker but
    would kill a scan in progress if a second worker started beside it.
    """
    if recover:
        recovered = job_queue.recover_stale()
        if recovered:
            print(f"[{label}] marked {recovered} interrupted job(s) as failed", flush=True)
        stale = _clear_stale_summaries()
        if stale:
            print(f"[{label}] released {stale} summary(ies) stuck pending", flush=True)

    print(f"[{label}] ready, polling every {POLL_SECONDS}s", flush=True)

    while not _stop:
        try:
            job = job_queue.claim_next()
        except Exception as e:
            # A database blip should not kill the worker; back off and retry.
            print(f"[{label}] queue unavailable ({type(e).__name__}: {e}), retrying", flush=True)
            time.sleep(POLL_SECONDS * 5)
            continue

        if not job:
            time.sleep(POLL_SECONDS)
            continue

        print(f"[{label}] scanning {job['repo']} (job {job['id'][:8]})", flush=True)
        started = time.time()
        try:
            result = scan_repo(
                job["repo"],
                job["archive_password"] or "infected",
                on_progress=lambda stage, _id=job["id"]: job_queue.set_stage(_id, stage),
            )
            job_queue.finish(job["id"], result["repo_id"])
            print(f"[{label}] done {job['repo']} in {time.time()-started:.0f}s", flush=True)

            # The summary runs after the job is marked finished, so the
            # visitor reaches the results page as soon as the scan is done
            # rather than waiting another 20-60s for CPU generation. The page
            # shows a placeholder until this lands.
            _write_summary(result["repo_id"], job["repo"], label)
        except Exception as e:
            # Every failure must land in the row, or the visitor's status page
            # spins forever on a job nobody is working on.
            job_queue.fail(job["id"], e)
            print(f"[{label}] FAILED {job['repo']}: {type(e).__name__}: {e}", flush=True)

    print(f"[{label}] stopped", flush=True)


def main():
    signal.signal(signal.SIGINT, _handle_stop)
    signal.signal(signal.SIGTERM, _handle_stop)
    run_forever(recover=True, label="worker")


if __name__ == "__main__":
    sys.exit(main())
