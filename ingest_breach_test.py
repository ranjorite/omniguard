"""Clones omniguard.rl into an isolated test store and ingests purple-team breach telemetry."""
import json
import shutil
from pathlib import Path
import relate

from omniguard_runtime import resolve_db_path
SOURCE_DB = resolve_db_path()
TEST_DB = Path("omniguard_purple_test.rl")


def ingest_events_to_test_graph(jsonl_path: Path, target_db: Path = TEST_DB) -> int:
    if not SOURCE_DB.exists():
        raise FileNotFoundError(f"Base store not found: {SOURCE_DB}")
    shutil.copy2(SOURCE_DB, target_db)

    events = [
        json.loads(line)
        for line in jsonl_path.read_text(encoding="utf-8").strip().splitlines()
        if line.strip()
    ]
    if not events:
        raise ValueError("No events found in JSONL file.")

    conn = relate.connect(str(target_db))
    cur = conn.cursor()

    # 1. Seed staging-breach ontology nodes (Rules, Controls, Frameworks, LogSource, Agent)
    cur.execute("""
    MERGE (a:Agent {name: 'StagingPortalApp'})
      SET a.role = 'web_portal', a.network_zone = 'staging_dmz'
    MERGE (ls:LogSource {source_id: 'SRC_STG_WEB_01'})
      SET ls.system_name = 'StagingCareerPortal', ls.collector = 'WazuhWebAgent',
          ls.log_category = 'application_access', ls.zone = 'staging_dmz'
    MERGE (p:Policy {policy_id: 'POL_STG_SEC'})
      SET p.name = 'Staging & PII Export Governance Policy'
    MERGE (fw_nist:Framework {framework_id: 'FW_NIST_800_53'})
      SET fw_nist.name = 'NIST SP 800-53'
    MERGE (fw_cdmc:Framework {framework_id: 'FW_CDMC'})
      SET fw_cdmc.name = 'CDMC'
    MERGE (fw_owasp:Framework {framework_id: 'FW_OWASP_2025'})
      SET fw_owasp.name = 'OWASP Top 10:2025'

    MERGE (c_ia57:Control {control_id: 'CTRL_NIST_IA5_7'})
      SET c_ia57.code = 'NIST-800-53-IA-5(7)', c_ia57.title = 'No Embedded Unencrypted Static Authenticators'
    MERGE (c_owasp:Control {control_id: 'CTRL_OWASP_A02'})
      SET c_owasp.code = 'OWASP-2025-A02', c_owasp.title = 'Security Misconfiguration (Active Debug Code)'
    MERGE (c_cdmc4:Control {control_id: 'CTRL_CDMC_04'})
      SET c_cdmc4.code = 'CDMC-04', c_cdmc4.title = 'Data Protection & Bulk Export Governance'
    MERGE (c_ia5:Control {control_id: 'CTRL_NIST_IA5'})
      SET c_ia5.code = 'NIST-800-53-IA-5', c_ia5.title = 'Authenticator Management'

    MERGE (c_ia57)-[:BELONGS_TO]->(fw_nist)
    MERGE (c_ia5)-[:BELONGS_TO]->(fw_nist)
    MERGE (c_owasp)-[:BELONGS_TO]->(fw_owasp)
    MERGE (c_cdmc4)-[:BELONGS_TO]->(fw_cdmc)

    MERGE (r_code:Rule {rule_id: 'RULE_STG_01'})
      SET r_code.code = 'STG-01', r_code.description = 'No hardcoded static credentials in public web code'
    MERGE (r_pii:Rule {rule_id: 'RULE_PII_01'})
      SET r_pii.code = 'PII-01', r_pii.description = 'Block unencrypted bulk PII exports using exposed credentials'

    MERGE (p)-[:CONTAINS]->(r_code)
    MERGE (p)-[:CONTAINS]->(r_pii)
    MERGE (r_code)-[:MAPS_TO]->(c_ia57)
    MERGE (r_code)-[:MAPS_TO]->(c_owasp)
    MERGE (r_pii)-[:MAPS_TO]->(c_cdmc4)
    MERGE (r_pii)-[:MAPS_TO]->(c_ia5)

    MERGE (de_cred:DataElement {elem_id: 'ELEM_ADMIN_CRED'})
      SET de_cred.name = 'ADMIN_CREDENTIAL', de_cred.classification = 'SECRET', de_cred.is_sad = false
    MERGE (de_pii:DataElement {elem_id: 'ELEM_PERSONNEL_PII'})
      SET de_pii.name = 'PERSONNEL_PII_RECORDS', de_pii.classification = 'RESTRICTED_PII', de_pii.is_sad = false

    MERGE (r_code)-[:PROTECTS]->(de_cred)
    MERGE (r_pii)-[:PROTECTS]->(de_pii)
    """)

    # 2. Ingest each JSONL event as a :Usage node linked to :Credential and :DataElement
    ingested = 0
    for idx, ev in enumerate(events, start=1):
        usage_id = f"BREACH_SIM_{idx:02d}"
        cred_id = ev["credential_id"]
        is_admin = cred_id == "CRED_STG_ADMIN_01"
        cred_status = "EXPOSED" if is_admin else "ACTIVE"
        key_age = 120 if is_admin else 0

        cur.execute(
            """
            MATCH (a:Agent {name: 'StagingPortalApp'})
            MATCH (ls:LogSource {source_id: 'SRC_STG_WEB_01'})
            MATCH (de:DataElement {name: $elem_name})
            MERGE (c:Credential {cred_id: $cred_id})
              SET c.cred_type = $cred_type, c.key_age_days = $key_age,
                  c.max_age_days = 90, c.status = $cred_status,
                  c.allowed_targets = 'staging_internal'
            MERGE (u:Usage {usage_id: $usage_id})
              SET u.log_type = $log_type, u.action = $action, u.protocol = $protocol,
                  u.outcome = $outcome, u.redacted_payload = $detail
            MERGE (a)-[:EMITTED]->(u)
            MERGE (ls)-[:COLLECTED]->(u)
            MERGE (c)-[:AUTHENTICATED]->(u)
            MERGE (u)-[:EXPOSES]->(de)
            """,
            {
                "usage_id": usage_id,
                "cred_id": cred_id,
                "cred_type": "static_admin_token" if is_admin else "anonymous_session",
                "key_age": key_age,
                "cred_status": cred_status,
                "log_type": ev["log_type"],
                "action": ev["action"],
                "protocol": ev["protocol"],
                "outcome": ev["outcome"],
                "detail": ev["detail"],
                "elem_name": ev["data_element"],
            },
        )
        ingested += 1

    # 3. Link causal kill-chain: landing-page leak ENABLED the bulk admin export
    cur.execute(
        """
        MATCH (u1:Usage {usage_id: 'BREACH_SIM_01'})
        MATCH (u2:Usage {usage_id: 'BREACH_SIM_02'})
        MERGE (u1)-[:ENABLED {reason: 'Hardcoded staging token in HTML comment enabled /admin/export'}]->(u2)
        """
    )

    conn.commit()
    conn.close()
    return ingested
