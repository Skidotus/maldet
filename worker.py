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
import re
import shutil
import subprocess
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

# ClamAV signature refresh, every N hours while idle; 0 (the default) is off.
# docker/entrypoint.sh only downloads signatures when none exist, and the
# Docker volume keeps them, so before this the VPS scanned with whatever it
# fetched on its first start: on 2026-11-09 that was 1 November, and nothing
# would ever have updated it. Antivirus signatures a week old miss a week of
# new malware, and nothing on the page would say so.
#
# Done here rather than at container start because the app and worker
# containers share the signature volume and both run the entrypoint, so two
# freshclams would race over one directory. Only the worker runs this, only
# between scans (freshclam test-loads the database, ~1GB, which must not
# overlap a scan on the 4GB host), and docker-compose.yml turns it on for the
# worker alone. Off by default so a laptop's system ClamAV, which needs root
# to update, is left to its own freshclam service.
SIGNATURE_REFRESH_HOURS = float(os.environ.get("MALDET_CLAMAV_REFRESH_HOURS", "0"))
FRESHCLAM_TIMEOUT = 900

_stop = False
_last_signature_check = None


def _handle_stop(signum, frame):
    """Finish the scan in progress, then exit -- rather than orphaning it.

    A killed mid-scan job would be left 'running' and block the queue until
    the next restart's recover_stale(), so the polite path is to stop taking
    new work and let the current one finish.
    """
    global _stop
    _stop = True
    print("\n[worker] stop requested; finishing current scan then exiting", flush=True)


def _mark_pending(repo_id):
    """Say a summary is coming, if one actually is. True when claimed.

    is_available() checks Ollama is reachable and has the model, not merely
    that it is not disabled -- so the detail page never shows a spinner for a
    scan that will not produce a summary.
    """
    if not llm_summary.is_available():
        return False
    try:
        db = connect(autocommit=True)
        try:
            db.cursor().execute("""UPDATE risk_scores SET llm_summary_status = 'pending'
                                   WHERE repo_id = %s""", (repo_id,))
        finally:
            db.close()
        return True
    except Exception:
        return False


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


def refresh_signatures_if_due(label="worker", now=None):
    """Runs freshclam if SIGNATURE_REFRESH_HOURS have passed since the last
    attempt (or there has been none since start). Returns "off", "not due",
    "missing", "updated", "current" or "failed"; never raises.

    The attempt time is recorded before running, so a failing update (no
    network, a ClamAV mirror rate limit) waits for the next interval instead
    of being retried every poll."""
    global _last_signature_check
    if SIGNATURE_REFRESH_HOURS <= 0 or os.environ.get("SKIP_FRESHCLAM") == "1":
        return "off"
    now = time.monotonic() if now is None else now
    if (_last_signature_check is not None
            and now - _last_signature_check < SIGNATURE_REFRESH_HOURS * 3600):
        return "not due"
    _last_signature_check = now

    if not shutil.which("freshclam"):
        print(f"[{label}] ClamAV signature refresh skipped: freshclam is not installed", flush=True)
        return "missing"
    try:
        result = subprocess.run(["freshclam", "--stdout"], capture_output=True, text=True,
                                timeout=FRESHCLAM_TIMEOUT)
    except subprocess.TimeoutExpired:
        print(f"[{label}] ClamAV signature refresh timed out after {FRESHCLAM_TIMEOUT}s", flush=True)
        return "failed"
    except OSError as e:
        print(f"[{label}] ClamAV signature refresh failed: {type(e).__name__}: {e}", flush=True)
        return "failed"

    # freshclam: 0 = something was updated, 1 = already up to date.
    if result.returncode in (0, 1):
        status = "updated" if result.returncode == 0 else "current"
        # "daily.cld updated (version: 27451, ...)" and
        # "main.cvd database is up-to-date (version: 63, ...)" alike.
        versions = [f"{m.group(1)} {m.group(2)}" for m in
                    (re.search(r"(\w+\.c[vl]d)\b.*?version: (\d+)", l)
                     for l in result.stdout.splitlines()) if m]
        print(f"[{label}] ClamAV signatures {status}"
              f"{' (' + ', '.join(versions) + ')' if versions else ''}", flush=True)
        return status
    reason = next((l.strip() for l in reversed((result.stdout + result.stderr).splitlines())
                   if "ERROR" in l or "WARNING" in l), f"exit {result.returncode}")
    print(f"[{label}] ClamAV signature refresh failed: {reason[:200]}", flush=True)
    return "failed"


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
            # Idle is the only safe time: never alongside a scan's memory.
            refresh_signatures_if_due(label)
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
            # Claim the summary before marking the job finished, not after:
            # finishing is what sends the visitor to the results page, and if
            # the row still said "unavailable" at that moment the page would
            # render without a placeholder and never poll.
            expecting = _mark_pending(result["repo_id"])

            job_queue.finish(job["id"], result["repo_id"])
            print(f"[{label}] done {job['repo']} in {time.time()-started:.0f}s", flush=True)

            # Generated after the job is finished, so the visitor reaches the
            # results page as soon as the scan is done rather than waiting
            # another 20-60s for CPU generation.
            if expecting:
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
