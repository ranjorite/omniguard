"""Automated QA suite (Smoke, Positive, Negative, Schema, Isolation) for OmniGuard breach simulation."""
import json
import os
import re
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import HTTPServer
from pathlib import Path

import test_portal

REQUIRED_LOG_FIELDS = {
    "timestamp",
    "log_type",
    "source_system",
    "collector",
    "protocol",
    "action",
    "path",
    "credential_id",
    "data_element",
    "outcome",
    "detail",
}


class TestPortalSimulation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.TemporaryDirectory()
        cls.log_path = Path(cls.tmp_dir.name) / "portal_events.jsonl"
        cls.orig_log_file = test_portal.LOG_FILE
        test_portal.LOG_FILE = str(cls.log_path)

        # Bind to port 0 so OS assigns a free ephemeral port (zero port conflicts)
        cls.server = HTTPServer(("127.0.0.1", 0), test_portal.PaymentPortalHandler)
        cls.port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"

        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        test_portal.LOG_FILE = cls.orig_log_file
        cls.tmp_dir.cleanup()

    def setUp(self):
        if self.log_path.exists():
            self.log_path.unlink()

    # --- 1. ENVIRONMENT / PRE-FLIGHT ---
    def test_01_preflight_files_exist(self):
        self.assertTrue(Path("test_portal.py").exists(), "test_portal.py missing")
        self.assertTrue(Path("simulate_breach.py").exists(), "simulate_breach.py missing")
        self.assertTrue(Path("omniguard.rl").exists(), "omniguard.rl missing")

    # --- 2. SMOKE TEST ---
    def test_02_smoke_landing_page_200(self):
        with urllib.request.urlopen(f"{self.base_url}/", timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/html", resp.headers.get("Content-Type", ""))

    # --- 3. POSITIVE: FULL EXPLOIT CHAIN + LOG SCHEMA ---
    def test_03_positive_end_to_end_breach_and_jsonl_schema(self):
        # Step A: Scrape landing page
        html = urllib.request.urlopen(f"{self.base_url}/", timeout=5).read().decode("utf-8")
        match = re.search(r"debug_export=([^\s]+)", html)
        self.assertIsNotNone(match, "Expected leaked debug_export path in landing page HTML")
        leaked_path = match.group(1)

        # Step B: Exfiltrate via leaked admin endpoint
        with urllib.request.urlopen(f"{self.base_url}{leaked_path}", timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            payload = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(payload["records_exported"], 2500)

        # Step C: Validate JSONL telemetry schema
        lines = self.log_path.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 2, f"Expected 2 log events, got {len(lines)}")
        events = [json.loads(line) for line in lines]

        for ev in events:
            self.assertTrue(REQUIRED_LOG_FIELDS.issubset(ev.keys()), f"Missing keys in {ev}")

        self.assertEqual(events[0]["action"], "VIEW_LANDING_PAGE")
        self.assertEqual(events[0]["outcome"], "EXPOSED_IN_HTML")
        self.assertEqual(events[1]["action"], "BULK_ADMIN_EXPORT")
        self.assertEqual(events[1]["outcome"], "SUCCESS_2500_RECORDS")

    # --- 4. NEGATIVE TESTS ---
    def test_04_negative_missing_token_returns_403(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(f"{self.base_url}/admin/export", timeout=5)
        self.assertEqual(ctx.exception.code, 403)
        self.assertFalse(self.log_path.exists(), "Failed auth should not log a successful export")

    def test_05_negative_wrong_token_returns_403(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(f"{self.base_url}/admin/export?token=INVALID_KEY", timeout=5)
        self.assertEqual(ctx.exception.code, 403)

    def test_06_negative_empty_token_returns_403(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(f"{self.base_url}/admin/export?token=", timeout=5)
        self.assertEqual(ctx.exception.code, 403)

    def test_07_negative_unknown_route_returns_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(f"{self.base_url}/does-not-exist", timeout=5)
        self.assertEqual(ctx.exception.code, 404)

    def test_08_negative_unsupported_post_returns_501(self):
        req = urllib.request.Request(f"{self.base_url}/admin/export", data=b"{}", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 501)

    # --- 5. ISOLATION / SAFETY ---
    def test_09_isolation_omniguard_store_untouched(self):
        store = Path("omniguard.rl")
        before = (store.stat().st_size, store.stat().st_mtime_ns)
        urllib.request.urlopen(f"{self.base_url}/", timeout=5).read()
        after = (store.stat().st_size, store.stat().st_mtime_ns)
        self.assertEqual(before, after, "omniguard.rl should never be mutated by portal tests")


if __name__ == "__main__":
    unittest.main(verbosity=2)
