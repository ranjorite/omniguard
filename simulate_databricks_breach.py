import argparse, json
from datetime import datetime, timezone
from omniguard_runtime import query_relate_rows, resolve_db_path

FRAMEWORK_PLAYBOOK = {
  "CDMC": "Trace lineage from exposed token to CustomerPII/CDE assets, freeze downstream ETL/Lakehouse jobs, and log steward impact.",
  "NIST_800_53": "Enforce IA-5 authenticator revocation/rotation, AC-6 least privilege, AC-7 failed-access lockouts, and AU-14 immutable audit archiving.",
  "PCI_DSS": "When CDE scope is linked, rotate cardholder/payment keys, verify network/token isolation, and retain forensic audit trails.",
  "MITRE_ATTACK": "Map exposure to T1552 (Unsecured Credentials), replay to T1078 (Valid Accounts), and data access attempt to T1530 (Cloud Storage/Warehouse).",
  "OWASP": "Enforce A01 (Broken Access Control) and A07 (Identification/Authentication Failures) with immediate token denial and secret scrubbing.",
}

def _rows(res):
  if not res: return []
  if isinstance(res, list) and res and isinstance(res[0], (tuple, list, dict)): return res
  lines = [str(x).strip() for x in res if str(x).strip().startswith('|')]
  if len(lines) < 2: return []
  hdr = [h.strip() for h in lines[0].strip('|').split('|')]
  out = []
  for ln in lines[1:]:
    cells = [c.strip().strip('"') for c in ln.strip('|').split('|')]
    if len(cells) == len(hdr): out.append(dict(zip(hdr, cells)))
  return out

def run_databricks_demo(db_path=None, token_id="CRED_DBX_PAT_01", channel="git_and_ai_chat"):
  target = resolve_db_path(db_path)
  ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
  qs = [f"MERGE (c:Credential {{cred_id: '{token_id}'}}) SET c.cred_type = 'pat_token', c.allowed_targets = 'DatabricksWarehouse', c.key_age_days = 15, c.max_age_days = 90, c.status = 'EXPOSED';", f"MERGE (u1:Usage {{usage_id: 'DBX_EXP_01'}}) SET u1.action = 'TOKEN_EXPOSED_T1552_{channel}', u1.log_type = 'databricks_audit', u1.outcome = 'EXPOSED', u1.protocol = 'HTTPS', u1.redacted_payload = 'cred_id={token_id} channel={channel} scope=CustomerPII(dob,phone,email)', u1.timestamp = '{ts}';", f"MERGE (u2:Usage {{usage_id: 'DBX_ATTEMPT_01'}}) SET u2.action = 'REPLAY_BLOCKED_T1078_T1530', u2.log_type = 'databricks_audit', u2.outcome = 'BLOCKED', u2.protocol = 'HTTPS', u2.redacted_payload = 'cred_id={token_id} target=CustomerPII outcome=BLOCKED', u2.timestamp = '{ts}';", f"MATCH (c:Credential {{cred_id: '{token_id}'}}) SET c.status = 'REVOKED';"]
  for qy in qs: query_relate_rows(qy, target)
  creds = _rows(query_relate_rows(f"MATCH (c:Credential {{cred_id: '{token_id}'}}) RETURN c.cred_id, c.status, c.allowed_targets;", target))
  usages = _rows(query_relate_rows(f"MATCH (u:Usage) WHERE u.usage_id STARTS WITH 'DBX_' RETURN u.usage_id, u.action, u.outcome;", target))
  return {"database": str(target), "timestamp": ts, "token_id": token_id, "channel": channel, "credentials": creds, "usages": usages, "next_steps": FRAMEWORK_PLAYBOOK}

def main():
  ap = argparse.ArgumentParser()
  ap.add_argument("--db", default=str(resolve_db_path()))
  ap.add_argument("--token", default="CRED_DBX_PAT_01")
  ap.add_argument("--channel", default="git_and_ai_chat")
  args = ap.parse_args()
  print(json.dumps(run_databricks_demo(args.db, args.token, args.channel), indent=2))

if __name__ == "__main__": main()
