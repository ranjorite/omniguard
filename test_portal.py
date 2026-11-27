import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from omniguard_runtime import BASE_DIR, is_credential_revoked, resolve_db_path

DB_PATH = resolve_db_path()
LOG_FILE = os.environ.get("OMNIGUARD_PORTAL_LOG", str(BASE_DIR / "logs" / "portal_events.jsonl"))
HOST = "127.0.0.1"
PORT = 8080
VALID_TOKENS = {"STG_ADMIN_TOKEN_DEMO", "CRED_STG_ADMIN_01"}


def _append_event(record: dict):
    target = Path(LOG_FILE)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


class PaymentPortalHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        now_iso = datetime.now(timezone.utc).isoformat()
        user_agent = self.headers.get("User-Agent", "UNKNOWN")

        if parsed.path == "/":
            token = "STG_ADMIN_TOKEN_DEMO"
            export_path = f"/admin/export?token={token}"
            _append_event({
                "timestamp": now_iso,
                "log_type": "web_access",
                "source_system": "StagingCareerPortal",
                "collector": "WazuhWebAgent",
                "protocol": self.request_version,
                "action": "VIEW_LANDING_PAGE",
                "path": parsed.path,
                "credential_id": "CRED_STG_ADMIN_01",
                "data_element": "ADMIN_CREDENTIAL",
                "outcome": "EXPOSED_IN_HTML",
                "detail": f"Landing page exposed debug_export={export_path}",
            })
            body = f"<html><body><!-- debug_export={export_path} --><a href='{export_path}'>Export</a></body></html>".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path != "/admin/export":
            body = b"Not Found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        header_key = self.headers.get("X-API-Key")
        query_token = qs.get("token", [None])[0]
        token = header_key if header_key is not None else query_token

        if not token or not str(token).strip() or str(token).strip() not in VALID_TOKENS:
            payload = {
                "status": "error",
                "code": 403,
                "reason": "Missing or invalid token",
            }
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        cred_id = "CRED_STG_ADMIN_01"
        if is_credential_revoked(cred_id, DB_PATH) or is_credential_revoked(str(token).strip(), DB_PATH):
            payload = {
                "status": "error",
                "code": 403,
                "reason": "Credential revoked by OmniGuard SOAR-CRED-REVOKE-01",
                "credential": cred_id,
            }
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        payload = {
            "status": "ok",
            "system": "PaymentGatewayAPI",
            "data_classification": "CDE_CARDHOLDER_DATA",
            "records_exported": 2500,
        }
        _append_event({
            "timestamp": now_iso,
            "log_type": "portal_export",
            "source_system": "PaymentGatewayAPI",
            "collector": "WazuhWebAgent",
            "protocol": self.request_version,
            "action": "BULK_ADMIN_EXPORT",
            "path": parsed.path,
            "credential_id": cred_id,
            "data_element": "PERSONNEL_PII_RECORDS",
            "outcome": "SUCCESS_2500_RECORDS",
            "detail": f"Exported 2500 records using {cred_id} (UA={user_agent})",
        })
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format, *args):
        return


PortalHandler = PaymentPortalHandler

if __name__ == "__main__":
    print(f"[PORTAL] PaymentGatewayAPI listening on http://{HOST}:{PORT}/admin/export")
    print(f"[PORTAL] Live policy backing store: {resolve_db_path(DB_PATH)}")
    HTTPServer((HOST, PORT), PaymentPortalHandler).serve_forever()
