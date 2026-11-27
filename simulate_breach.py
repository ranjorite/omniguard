import json
import time
import urllib.error
import urllib.request
from pathlib import Path

from omniguard_runtime import query_relate_rows, resolve_db_path

DB_PATH = resolve_db_path()
PORTAL_URL = "http://127.0.0.1:8080/admin/export"
STOLEN_KEY = "CRED_STOLEN_PAY_01"


def run_cypher(query: str) -> str:
    rows = query_relate_rows(query, DB_PATH)
    return "\n".join(str(x) for r in rows for x in (r if isinstance(r, (list, tuple)) else [r])).strip()


def send_attack_request(attempt_num: int) -> int:
    req = urllib.request.Request(
        PORTAL_URL,
        headers={
            "X-API-Key": STOLEN_KEY,
            "User-Agent": "BlackSun",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            print(f"[ATTACKER - Attempt {attempt_num}] HTTP {resp.status} -> {body}")
            return resp.status
    except urllib.error.HTTPError as err:
        body = json.loads(err.read().decode("utf-8"))
        print(f"[ATTACKER - Attempt {attempt_num}] HTTP {err.code} -> {body}")
        return err.code


def main():
    print("=== 1. Resetting Demo State in Relate ===")
    run_cypher(
        f'MERGE (s:System {{name: "PaymentGatewayAPI"}}) '
        f'MERGE (a:DataAsset {{name: "CardholderVault", classification: "CDE"}}) '
        f'MERGE (s)-[:STORES]->(a) '
        f'MERGE (c:Credential {{id: "{STOLEN_KEY}"}}) '
        f'SET c.status = "ACTIVE", c.owner = "svc_payments";'
    )
    print(f"[SETUP] {STOLEN_KEY} is ACTIVE on PaymentGatewayAPI (CDE).\n")

    print("=== 2. Strike 1: Attacker Uses Stolen Key (Before Containment) ===")
    send_attack_request(1)
    time.sleep(1.5)

    print("\n=== 3. OmniGuard Graph Detection & SOAR Containment ===")
    print("[OMNIGUARD] Detected P1_ALERT: BlackSun UA accessing CDE (CardholderVault)")
    print("[OMNIGUARD] Firing Playbook: SOAR-CRED-REVOKE-01 -> Revoking credential in Relate...")
    run_cypher(
        f'MATCH (s:System {{name: "PaymentGatewayAPI"}}), '
        f'(a:DataAsset {{name: "CardholderVault"}}), '
        f'(c:Credential {{id: "{STOLEN_KEY}"}}) '
        f'MERGE (u:Usage {{id: "BREACH_LIVE_01"}}) '
        f'SET u.source = "portal_waf", u.severity = "P1_ALERT", '
        f'u.description = "Unauthorized CDE export via BlackSun UA" '
        f'MERGE (u)-[:USED_CREDENTIAL]->(c) '
        f'MERGE (u)-[:ON_SYSTEM]->(s) '
        f'MERGE (u)-[:ACCESSED_ASSET]->(a) '
        f'MERGE (cc:ComplianceControl {{framework: "PCI_DSS", control_id: "10.2.5"}}) '
        f'MERGE (u)-[:VIOLATES_CONTROL]->(cc) '
        f'SET c.status = "REVOKED", c.revoked_by = "SOAR-CRED-REVOKE-01";'
    )
    time.sleep(1.5)

    print("\n=== 4. Strike 2: Attacker Retries Exact Same Request ===")
    send_attack_request(2)

    print("\n=== 5. Graph Proof Inside Relate ===")
    proof = run_cypher(
        f'MATCH (u:Usage {{id: "BREACH_LIVE_01"}})-[:USED_CREDENTIAL]->(c:Credential), '
        f'(u)-[:VIOLATES_CONTROL]->(cc:ComplianceControl) '
        f'RETURN c.id, c.status, c.revoked_by, cc.framework, cc.control_id;'
    )
    print(proof)


if __name__ == "__main__":
    main()
