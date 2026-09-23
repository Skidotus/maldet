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

import job_queue
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
