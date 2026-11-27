import json
from pathlib import Path
from omniguard_runtime import BASE_DIR, query_relate_rows, resolve_db_path

DB_PATH = resolve_db_path()
WAZUH_LOG = Path(BASE_DIR / "logs" / "wazuh_alerts.jsonl")

FRAMEWORK_SCOPE_REQ = {
    "pci_dss": ("PCI_DSS", "CDE"),
    "hipaa": ("HIPAA", "ePHI"),
    "gdpr": ("GDPR", "PII"),
    "nist_800_53": ("NIST_800_53", "ENTERPRISE"),
    "tsc": ("SOC2_TSC", "ENTERPRISE"),
}

SENSITIVE_PATTERNS = ("passwords.txt", ".env", "id_rsa", "credentials", "secret")

def run_cypher(query: str, db_path=None) -> list:
    target = resolve_db_path(db_path or DB_PATH)
    if not target.exists(): return []
    return query_relate_rows(query, target)

def resolve_system_scope(system_name: str, db_path=None) -> set:
    scopes = {"ENTERPRISE"}
    safe_sys = str(system_name or "").replace(chr(34), "").replace(chr(39), "").strip()
    if safe_sys:
        cypher = f"OPTIONAL MATCH (s:System {{name: {safe_sys!r}}})-[:STORES]->(d) RETURN coalesce(d.classification, d.scope, s.scope);"
        for row in run_cypher(cypher, db_path):
            for v in (row if isinstance(row, (list, tuple)) else [row]):
                if v and str(v).strip().upper() not in {"NONE", "NULL", ""}:
                    scopes.add(str(v).strip())
    up = safe_sys.upper()
    if any(k in up for k in ("PAY", "CARD", "CDE")): scopes.update({"CDE", "PII"})
    if any(k in up for k in ("HEALTH", "HIPAA", "EPHI", "PHI")): scopes.update({"ePHI", "PII"})
    if any(k in up for k in ("PORTAL", "USER", "CUSTOMER", "HR", "PII")): scopes.add("PII")
    return scopes

def map_wazuh_alert(alert: dict) -> dict:
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})

    event_id = f"WAZUH_{alert.get('id', '0').replace('.', '_')}"
    system_name = agent.get("name", "UNKNOWN_HOST")
    user = data.get("srcuser") or data.get("dstuser") or data.get("src_ip") or "system"
    cred_id = f"CRED_{system_name}_{user}".upper()
    command = data.get("command", "")
    host_scopes = resolve_system_scope(system_name, DB_PATH)

    is_suricata = "suricata" in rule.get("groups", [])
    matched_secret = next((p for p in SENSITIVE_PATTERNS if p in command.lower()), None)

    if is_suricata or rule.get("level", 0) >= 10:
        severity = "P1_ALERT"
    elif matched_secret:
        severity = "P2_SECRET_ACCESS"
    else:
        severity = "NORMAL_BASELINE"

    applicable_controls = []
    suppressed_controls = []

    for raw_key, (fw_name, req_scope) in FRAMEWORK_SCOPE_REQ.items():
        controls = rule.get(raw_key, [])
        if not controls:
            continue
        if req_scope in host_scopes:
            # Only persist active violations for escalated events; baseline stays audit-only
            if severity != "NORMAL_BASELINE":
                for cid in controls:
                    applicable_controls.append((fw_name, cid))
        else:
            suppressed_controls.append(f"{fw_name}({len(controls)})")

    mitre = rule.get("mitre", {})
    mitre_entries = list(zip(
        mitre.get("id", []),
        mitre.get("tactic", ["Unknown"] * len(mitre.get("id", []))),
        mitre.get("technique", ["Unknown"] * len(mitre.get("id", []))),
    ))

    return {
        "event_id": event_id,
        "system": system_name,
        "credential": cred_id,
        "rule_id": rule.get("id", ""),
        "description": rule.get("description", ""),
        "secret_target": matched_secret or "",
        "severity": severity,
        "applicable_controls": applicable_controls,
        "suppressed_controls": suppressed_controls,
        "mitre_entries": mitre_entries,
    }


def ingest_wazuh() -> None:
    if not WAZUH_LOG.exists():
        print(f"[!] Missing {WAZUH_LOG}. Export alerts.json first.")
        return

    total, total_suppressed, total_controls_linked, total_mitre_linked = 0, 0, 0, 0

    with WAZUH_LOG.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = map_wazuh_alert(json.loads(line))
            total += 1
            total_suppressed += len(rec["suppressed_controls"])

            desc_safe = rec["description"].replace('"', '\\"')
            cypher_parts = [
                f'MERGE (s:System {{name: "{rec["system"]}"}})',
                f'MERGE (c:Credential {{id: "{rec["credential"]}"}})',
                f'MERGE (u:Usage {{id: "{rec["event_id"]}"}})',
                f'SET u.source = "wazuh", u.rule_id = "{rec["rule_id"]}", '
                f'u.description = "{desc_safe}", u.severity = "{rec["severity"]}"',
                'MERGE (u)-[:USED_CREDENTIAL]->(c)',
                'MERGE (u)-[:ON_SYSTEM]->(s)',
            ]

            if rec["secret_target"]:
                cypher_parts.append(
                    f'MERGE (a:DataAsset {{name: "{rec["secret_target"]}", classification: "SECRET"}})'
                    f' MERGE (u)-[:ACCESSED_ASSET]->(a)'
                )

            for idx, (fw, cid) in enumerate(rec["applicable_controls"]):
                total_controls_linked += 1
                cypher_parts.append(
                    f'MERGE (cc{idx}:ComplianceControl {{framework: "{fw}", control_id: "{cid}"}})'
                    f' MERGE (u)-[:VIOLATES_CONTROL]->(cc{idx})'
                )

            for idx, (mid, tactic, tech) in enumerate(rec["mitre_entries"]):
                total_mitre_linked += 1
                t_safe = tactic.replace('"', '\\"')
                tech_safe = tech.replace('"', '\\"')
                cypher_parts.append(
                    f'MERGE (m{idx}:MITRETechnique {{id: "{mid}", tactic: "{t_safe}", technique: "{tech_safe}"}})'
                    f' MERGE (u)-[:USES_TECHNIQUE]->(m{idx})'
                )

            run_cypher(" ".join(cypher_parts) + ";")

            print(
                f"[{rec['severity']}] {rec['event_id']} | "
                f"Active Controls={len(rec['applicable_controls'])} | "
                f"Suppressed={', '.join(rec['suppressed_controls']) or 'None'}"
            )

    print("\n--- Multi-Framework Ingestion Summary ---")
    print(f"Total Wazuh events mapped          : {total}")
    print(f"Out-of-scope framework noise killed: {total_suppressed} (PCI DSS, HIPAA, GDPR)")
    print(f"In-scope controls linked in Relate : {total_controls_linked} (NIST 800-53, SOC 2 TSC)")
    print(f"MITRE ATT&CK techniques linked     : {total_mitre_linked}")


if __name__ == "__main__":
    ingest_wazuh()
