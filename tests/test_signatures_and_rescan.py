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
# What the VPS printed on 2026-11-09, exit code 0, nothing downloaded.
CURRENT = ("daily.cld database is up-to-date (version: 28178, sigs: 355854, f-level: 90, builder: x)\n"
           "main.cvd database is up-to-date (version: 63, sigs: 3287027, f-level: 90, builder: x)\n"
           "bytecode.cvd database is up-to-date (version: 339, sigs: 80, f-level: 90, builder: x)\n"
           "ERROR: NotifyClamd: Can't find or parse configuration file /etc/clamav/clamd.conf\n")


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

    def test_up_to_date_is_reported_as_current_whatever_the_exit_code(self):
        """freshclam 1.4 exits 0 when nothing changed, which the VPS logged as
        'updated'. The per-database lines decide, not the exit code."""
        for code in (0, 1):
            worker._last_signature_check = None
            with mock.patch.object(worker.subprocess, "run", return_value=ran(code, CURRENT)):
                self.assertEqual(worker.refresh_signatures_if_due(now=0), "current", code)

    def test_a_changed_database_is_reported_as_updated_whatever_the_exit_code(self):
        for code in (0, 1):
            worker._last_signature_check = None
            with mock.patch.object(worker.subprocess, "run", return_value=ran(code, UPDATED)):
                self.assertEqual(worker.refresh_signatures_if_due(now=0), "updated", code)

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

    def test_post_with_this_browsers_token_queues_the_scan(self):
        token = "t" * 43
        self.client.set_cookie(app_module.CSRF_COOKIE, token)
        with mock.patch.object(app_module, "_start_scan_job", return_value="abc123") as start:
            resp = self.client.post("/rescan/7", data={app_module.CSRF_FIELD: token})
        start.assert_called_once_with("pallets/flask", "infected")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("abc123", resp.headers["Location"])

    def test_cross_site_post_without_a_matching_token_never_starts_a_scan(self):
        """What another website can send: the visitor's cookies come along,
        but it cannot read them to copy the token into the form."""
        self.client.set_cookie(app_module.CSRF_COOKIE, "t" * 43)
        for data in ({}, {app_module.CSRF_FIELD: ""}, {app_module.CSRF_FIELD: "x" * 43}):
            with mock.patch.object(app_module, "_start_scan_job") as start:
                resp = self.client.post("/rescan/7", data=data)
            start.assert_not_called()
            self.assertTrue(resp.headers["Location"].endswith("/detail/7"))

    def test_no_cookie_means_no_scan_even_with_a_guessed_field(self):
        with mock.patch.object(app_module, "_start_scan_job") as start:
            self.client.post("/rescan/7", data={app_module.CSRF_FIELD: ""})
        start.assert_not_called()


class ScanFormCsrfTests(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()
        patches = [mock.patch.object(app_module, "_visitor_job_id", return_value=None),
                   mock.patch.object(app_module, "_repo_size_mb", return_value=None)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_form_page_issues_a_token_in_cookie_and_field(self):
        resp = self.client.get("/scan")
        cookie = self.client.get_cookie(app_module.CSRF_COOKIE)
        self.assertIsNotNone(cookie)
        self.assertGreaterEqual(len(cookie.value), 32)
        self.assertTrue(cookie.http_only)
        self.assertIn(f'name="csrf_token" value="{cookie.value}"', resp.get_data(as_text=True))

    def test_token_is_stable_across_pages(self):
        self.client.get("/scan")
        first = self.client.get_cookie(app_module.CSRF_COOKIE).value
        resp = self.client.get("/scan?repo=pallets/flask")
        self.assertEqual(self.client.get_cookie(app_module.CSRF_COOKIE).value, first)
        self.assertIn(first, resp.get_data(as_text=True))

    def test_forged_scan_is_refused_and_the_form_comes_back_filled_in(self):
        self.client.set_cookie(app_module.CSRF_COOKIE, "t" * 43)
        with mock.patch.object(app_module, "_start_scan_job") as start:
            resp = self.client.post("/scan", data={"repo_url": "pallets/flask"})
        start.assert_not_called()
        self.assertEqual(resp.status_code, 400)
        body = resp.get_data(as_text=True)
        self.assertIn("security cookie", body)
        self.assertIn('value="pallets/flask"', body)

    def test_genuine_scan_goes_through(self):
        resp = self.client.get("/scan")
        token = self.client.get_cookie(app_module.CSRF_COOKIE).value
        with mock.patch.object(app_module, "_start_scan_job", return_value="job1") as start:
            resp = self.client.post("/scan", data={"repo_url": "pallets/flask", "csrf_token": token})
        start.assert_called_once()
        self.assertIn("job1", resp.headers["Location"])

    def test_report_page_offers_rescan_as_a_post_form(self):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "templates", "detail.html")
        with open(path) as handle:
            html = handle.read()
        self.assertIn('<form method="post" action="{{ url_for(\'rescan\'', html)
        self.assertNotIn('<a href="{{ url_for(\'rescan\'', html)


if __name__ == "__main__":
    unittest.main()
