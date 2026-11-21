"""Intentionally vulnerable local staging portal for OmniGuard purple-team testing."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs

LOG_FILE = "portal_events.jsonl"
LEAKED_ADMIN_TOKEN = "STG_ADMIN_KEY_2026_EXPOSED"

def write_log(log_type: str, action: str, path: str, cred_id: str, element: str, outcome: str, detail: str):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "log_type": log_type,
        "source_system": "StagingCareerPortal",
        "collector": "WazuhWebAgent",
        "protocol": "HTTP",
        "action": action,
        "path": path,
        "credential_id": cred_id,
        "data_element": element,
        "outcome": outcome,
        "detail": detail,
    }
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

class PortalHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # keep console clean

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            # VULNERABILITY: Staging debug comment + hardcoded admin token left in landing page source
            html = f"""
            <html><body>
            <h1>Ex-Agniveer Career Portal (STAGING TEST)</h1>
            <!-- TODO: remove before prod! debug_export=/admin/export?token={LEAKED_ADMIN_TOKEN} -->
            <p>Portal under maintenance.</p>
            </body></html>
            """
            write_log("application", "VIEW_LANDING_PAGE", "/", "ANON_PUBLIC", "ADMIN_CREDENTIAL", "EXPOSED_IN_HTML", "Landing page served with hardcoded staging token in HTML comment")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))

        elif parsed.path == "/admin/export":
            token = parse_qs(parsed.query).get("token", [""])[0]
            if token == LEAKED_ADMIN_TOKEN:
                write_log("access", "BULK_ADMIN_EXPORT", "/admin/export", "CRED_STG_ADMIN_01", "PERSONNEL_PII_RECORDS", "SUCCESS_2500_RECORDS", "Bulk export of 2500 applicant records via exposed staging token over HTTP")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok", "records_exported": 2500, "sample": "SYNTHETIC_APPLICANT_0001"}).encode("utf-8"))
            else:
                self.send_response(403)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == "__main__":
    print("Starting vulnerable staging portal on http://127.0.0.1:5050 ...")
    HTTPServer(("127.0.0.1", 5050), PortalHandler).serve_forever()
