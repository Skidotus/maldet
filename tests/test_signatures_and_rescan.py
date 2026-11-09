"""Two fixes from 2026-11-09, both about things that happened without anyone
asking: ClamAV signatures that were never refreshed after a container's first
start, and a /rescan/<id> GET that queued a scan for any crawler or chat-app
link preview. No network, no database, no real freshclam.

    python3 -m unittest discover -s tests -t . -v
"""
import os
import subprocess
import unittest
from unittest import mock

import app as app_module
import worker

UPDATED = ("ClamAV update process started at Mon Nov  9 20:00:00 2026\n"
           "daily.cld updated (version: 27451, sigs: 2069001, f-level: 90, builder: raynman)\n"
           "main.cvd database is up-to-date (version: 62, sigs: 6647427, f-level: 90, builder: sigmgr)\n")


def ran(code, out=""):
    return subprocess.CompletedProcess(["freshclam"], code, stdout=out, stderr="")


class SignatureRefreshTests(unittest.TestCase):
    def setUp(self):
        patches = [mock.patch.object(worker, "_last_signature_check", None),
                   mock.patch.object(worker, "SIGNATURE_REFRESH_HOURS", 24),
                   mock.patch.object(worker.shutil, "which", return_value="/usr/bin/freshclam"),
                   mock.patch.dict(worker.os.environ, {"SKIP_FRESHCLAM": "0"})]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_off_by_default_and_with_skip_freshclam(self):
        with mock.patch.object(worker, "SIGNATURE_REFRESH_HOURS", 0), \
                mock.patch.object(worker.subprocess, "run") as run:
            self.assertEqual(worker.refresh_signatures_if_due(now=0), "off")
        with mock.patch.dict(worker.os.environ, {"SKIP_FRESHCLAM": "1"}), \
                mock.patch.object(worker.subprocess, "run") as run2:
            self.assertEqual(worker.refresh_signatures_if_due(now=0), "off")
        run.assert_not_called()
        run2.assert_not_called()

    def test_runs_at_start_then_once_per_interval(self):
        with mock.patch.object(worker.subprocess, "run", return_value=ran(0, UPDATED)) as run:
            self.assertEqual(worker.refresh_signatures_if_due(now=1000), "updated")
            self.assertEqual(worker.refresh_signatures_if_due(now=1000 + 3600), "not due")
            self.assertEqual(worker.refresh_signatures_if_due(now=1000 + 24 * 3600), "updated")
        self.assertEqual(run.call_count, 2)

    def test_up_to_date_is_exit_1_and_not_a_failure(self):
        with mock.patch.object(worker.subprocess, "run", return_value=ran(1, UPDATED)):
            self.assertEqual(worker.refresh_signatures_if_due(now=0), "current")

    def test_failure_waits_for_the_next_interval_instead_of_retrying_every_poll(self):
        with mock.patch.object(worker.subprocess, "run",
                               return_value=ran(62, "ERROR: Can't connect to port 443\n")) as run:
            self.assertEqual(worker.refresh_signatures_if_due(now=0), "failed")
            self.assertEqual(worker.refresh_signatures_if_due(now=10), "not due")
        self.assertEqual(run.call_count, 1)

    def test_timeout_and_missing_binary_never_raise(self):
        with mock.patch.object(worker.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("freshclam", 900)):
            self.assertEqual(worker.refresh_signatures_if_due(now=0), "failed")
        worker._last_signature_check = None
        with mock.patch.object(worker.shutil, "which", return_value=None):
            self.assertEqual(worker.refresh_signatures_if_due(now=0), "missing")

    def test_versions_are_reported(self):
        with mock.patch.object(worker.subprocess, "run", return_value=ran(0, UPDATED)), \
                mock.patch("builtins.print") as printed:
            worker.refresh_signatures_if_due(now=0)
        line = printed.call_args[0][0]
        self.assertIn("daily.cld 27451", line)
        self.assertIn("main.cvd 62", line)


class FakeCursor:
    def execute(self, *_args):
        pass

    def fetchone(self):
        return {"repo_name": "flask", "owner": "pallets"}

    def close(self):
        pass


class FakeDb:
    def cursor(self):
        return FakeCursor()

    def close(self):
        pass


class RescanRouteTests(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()
        patches = [mock.patch.object(app_module, "get_db", return_value=FakeDb()),
                   mock.patch.object(app_module, "_visitor_job_id", return_value=None),
                   mock.patch.object(app_module, "_repo_size_mb", return_value=None)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_get_never_starts_a_scan_and_lands_on_the_report(self):
        with mock.patch.object(app_module, "_start_scan_job") as start:
            resp = self.client.get("/rescan/7")
        start.assert_not_called()
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp.headers["Location"].endswith("/detail/7"))

    def test_head_from_a_link_preview_never_starts_a_scan(self):
        with mock.patch.object(app_module, "_start_scan_job") as start:
            self.client.head("/rescan/7")
        start.assert_not_called()

    def test_post_queues_the_scan(self):
        with mock.patch.object(app_module, "_start_scan_job", return_value="abc123") as start:
            resp = self.client.post("/rescan/7")
        start.assert_called_once_with("pallets/flask", "infected")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("abc123", resp.headers["Location"])

    def test_report_page_offers_rescan_as_a_post_form(self):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "templates", "detail.html")
        with open(path) as handle:
            html = handle.read()
        self.assertIn('<form method="post" action="{{ url_for(\'rescan\'', html)
        self.assertNotIn('<a href="{{ url_for(\'rescan\'', html)


if __name__ == "__main__":
    unittest.main()
