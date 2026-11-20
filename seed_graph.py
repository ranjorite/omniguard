"""
OmniGuard — Deterministic Graph Seeder & Pre-Ingestion Redactor
Builds omniguard.rl with multi-framework governance & security context:
  - PCI DSS v4.0.1 (Account data & SAD protection)
  - CDMC (Data classification, lineage & catalog governance)
  - NIST SP 800-53 / 800-57 / 800-92 (Logging provenance, access & key lifecycle)

Requires: pip install relate-db
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import random
import re
import shutil
import relate  # from package `relate-db`

DB_PATH = Path(__file__).resolve().parent / "omniguard.rl"

# ---------------------------------------------------------------------------
# 1. Pre-Ingestion Redaction Hygiene (No raw SAD, PAN, or private keys in DB)
# ---------------------------------------------------------------------------
_RE_CVV = re.compile(r"(?i)\b(cvv|cvc|cid)\s*[:=]\s*\d{3,4}\b")
_RE_PAN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_RE_PEM = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
)
_RE_KEY_KV = re.compile(
    r"(?i)\b(private_key|secret_key|api_secret|bearer)\s*[:=]\s*[^\s,;\"']+"
)


def redact_payload(raw_text: str) -> str:
    """Scrubs SAD (CVV), full PANs, and private key material before graph write."""
    text = _RE_PEM.sub("[REDACTED_PRIVATE_KEY_BLOCK]", raw_text)
    text = _RE_CVV.sub(lambda m: f"{m.group(1)}=[REDACTED_CVV]", text)
    text = _RE_KEY_KV.sub(lambda m: f"{m.group(1)}=[REDACTED_SECRET]", text)

    def _mask_pan(match: re.Match) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19:
            return f"****{digits[-4:]}"
        return match.group(0)

    return _RE_PAN.sub(_mask_pan, text)


# ---------------------------------------------------------------------------
# 2. Reference Frameworks, Controls, Policies, Rules & Data Elements
# ---------------------------------------------------------------------------
FRAMEWORKS = [
    {"id": "FW_PCI_4_0_1", "name": "PCI DSS v4.0.1", "domain": "Payment Data Security"},
    {"id": "FW_CDMC", "name": "CDMC", "domain": "Cloud Data Management & Governance"},
    {"id": "FW_NIST_800_53", "name": "NIST SP 800-53", "domain": "Security & Privacy Controls"},
    {"id": "FW_NIST_800_57", "name": "NIST SP 800-57", "domain": "Cryptographic Key Management"},
    {"id": "FW_NIST_800_92", "name": "NIST SP 800-92", "domain": "Security Log Management"},
]

CONTROLS = [
    {
        "id": "CTRL_PCI_3_3_1_2",
        "code": "PCI-3.3.1.2",
        "title": "SAD is not retained after authorization",
        "framework_id": "FW_PCI_4_0_1",
    },
    {
        "id": "CTRL_PCI_4_2_1",
        "code": "PCI-4.2.1",
        "title": "Strong cryptography protects PAN during transmission",
        "framework_id": "FW_PCI_4_0_1",
    },
    {
        "id": "CTRL_CDMC_CLASS_01",
        "code": "CDMC-04",
        "title": "Sensitive data classification & catalog governance",
        "framework_id": "FW_CDMC",
    },
    {
        "id": "CTRL_CDMC_PROT_02",
        "code": "CDMC-09",
        "title": "Automated data protection & masking in pipelines",
        "framework_id": "FW_CDMC",
    },
    {
        "id": "CTRL_NIST_800_53_AU2",
        "code": "NIST-800-53-AU-2",
        "title": "Auditable event generation & content hygiene",
        "framework_id": "FW_NIST_800_53",
    },
    {
        "id": "CTRL_NIST_800_53_IA5",
        "code": "NIST-800-53-IA-5",
        "title": "Authenticator management, rotation & compromise revocation",
        "framework_id": "FW_NIST_800_53",
    },
    {
        "id": "CTRL_NIST_800_53_SC8",
        "code": "NIST-800-53-SC-8",
        "title": "Transmission confidentiality and integrity",
        "framework_id": "FW_NIST_800_53",
    },
    {
        "id": "CTRL_NIST_800_57_CRYPTO",
        "code": "NIST-800-57-P1",
        "title": "Cryptoperiod enforcement & compromised key retirement",
        "framework_id": "FW_NIST_800_57",
    },
    {
        "id": "CTRL_NIST_800_92_PROV",
        "code": "NIST-800-92-S3",
        "title": "Log source provenance, categorization & secure collection",
        "framework_id": "FW_NIST_800_92",
    },
]

POLICIES = [
    {"id": "POL_STORED_SAD", "name": "Protect Stored Account Data"},
    {"id": "POL_TRANSIT_CHD", "name": "Protect Cardholder Data in Transit"},
    {"id": "POL_KEY_LIFECYCLE", "name": "Cryptographic Key & Credential Lifecycle"},
    {"id": "POL_CATALOG_ACCESS", "name": "Metadata Catalog & Lineage Access Governance"},
]

RULES = [
    {
        "id": "RULE_PCI_3_3_1_2",
        "code": "Req 3.3.1.2",
        "description": "Sensitive Authentication Data (CVV/CVC) must not be stored after authorization",
        "policy_id": "POL_STORED_SAD",
        "protects_elem": "ELEM_CVV",
        "maps_to_controls": ["CTRL_PCI_3_3_1_2", "CTRL_CDMC_PROT_02", "CTRL_NIST_800_53_AU2"],
    },
    {
        "id": "RULE_PCI_4_2_1",
        "code": "Req 4.2.1",
        "description": "PAN must be protected with strong cryptography during transmission",
        "policy_id": "POL_TRANSIT_CHD",
        "protects_elem": "ELEM_PAN",
        "maps_to_controls": ["CTRL_PCI_4_2_1", "CTRL_CDMC_PROT_02", "CTRL_NIST_800_53_SC8"],
    },
    {
        "id": "RULE_KEY_ROTATION_EXP",
        "code": "KEY-01",
        "description": "Private keys must be rotated within 90 days and revoked immediately if exposed",
        "policy_id": "POL_KEY_LIFECYCLE",
        "protects_elem": "ELEM_PRIV_KEY",
        "maps_to_controls": ["CTRL_NIST_800_57_CRYPTO", "CTRL_NIST_800_53_IA5"],
    },
    {
        "id": "RULE_CATALOG_GOV_01",
        "code": "CAT-02",
        "description": "Sensitive schema & lineage metadata requires non-expired, scoped credentials",
        "policy_id": "POL_CATALOG_ACCESS",
        "protects_elem": "ELEM_CATALOG_META",
        "maps_to_controls": ["CTRL_CDMC_CLASS_01", "CTRL_NIST_800_53_IA5", "CTRL_NIST_800_92_PROV"],
    },
]

DATA_ELEMENTS = [
    {"id": "ELEM_CVV", "name": "CVV", "classification": "SAD_RESTRICTED", "is_sad": True},
    {"id": "ELEM_PAN", "name": "PAN", "classification": "CHD_CONFIDENTIAL", "is_sad": False},
    {
        "id": "ELEM_PRIV_KEY",
        "name": "PRIVATE_SIGNING_KEY",
        "classification": "SECRET_CREDENTIAL",
        "is_sad": False,
    },
    {
        "id": "ELEM_CATALOG_META",
        "name": "CATALOG_LINEAGE_METADATA",
        "classification": "GOVERNED_METADATA",
        "is_sad": False,
    },
]


# ---------------------------------------------------------------------------
# 3. Log Sources, Agents & Credentials
# ---------------------------------------------------------------------------
LOG_SOURCES = [
    {
        "id": "SRC_APP_GW",
        "system_name": "PaymentGatewayCluster",
        "collector": "WazuhAppAgent",
        "log_category": "application",
        "zone": "cde",
    },
    {
        "id": "SRC_NET_IDS",
        "system_name": "InternalSegmentSensor",
        "collector": "WazuhSuricataCollector",
        "log_category": "network",
        "zone": "internal",
    },
    {
        "id": "SRC_ACC_CAT",
        "system_name": "MetadataCatalogGateway",
        "collector": "WazuhAuditdCollector",
        "log_category": "access",
        "zone": "metadata_tier",
    },
]

AGENTS = [
    {
        "id": "AGT_PAY_GW",
        "name": "PaymentGatewayAPI",
        "role": "Payment Processor",
        "network_zone": "cde",
    },
    {
        "id": "AGT_ANALYTICS_JOB",
        "name": "Analytics_Export_Job",
        "role": "Internal Data Sync",
        "network_zone": "internal",
    },
    {
        "id": "AGT_CATALOG_CLIENT",
        "name": "CatalogMetadataSync",
        "role": "Lineage & Metadata Consumer",
        "network_zone": "metadata_tier",
    },
    {
        "id": "AGT_CI_RUNNER",
        "name": "BuildPipelineWorker",
        "role": "Automation Runner",
        "network_zone": "internal",
    },
]

CREDENTIALS = [
    {
        "id": "CRED_GW_TLS_01",
        "cred_type": "mtls_client_cert",
        "key_age_days": 34,
        "max_age_days": 90,
        "status": "active",
        "allowed_targets": "PaymentGatewayAPI",
    },
    {
        "id": "CRED_SYNC_SVC_02",
        "cred_type": "service_token",
        "key_age_days": 45,
        "max_age_days": 90,
        "status": "active",
        "allowed_targets": "AnalyticsIngestEndpoint",
    },
    {
        "id": "CRED_CAT_PRIVKEY_99",
        "cred_type": "private_key",
        "key_age_days": 410,
        "max_age_days": 90,
        "status": "exposed",
        "allowed_targets": "MetadataCatalogService",
    },
    {
        "id": "CRED_CAT_ROTATED_04",
        "cred_type": "private_key",
        "key_age_days": 12,
        "max_age_days": 90,
        "status": "active",
        "allowed_targets": "MetadataCatalogService",
    },
]


# ---------------------------------------------------------------------------
# 4. Deterministic 32-Event Generator (Application, Network & Access Logs)
# ---------------------------------------------------------------------------
def build_usage_events() -> list[dict]:
    rng = random.Random(42)
    base_time = datetime(2026, 11, 18, 8, 0, 0, tzinfo=timezone.utc)
    events: list[dict] = []

    events.append(
        {
            "usage_id": "LOG_VIOLATION_01",
            "log_type": "application",
            "action": "DEBUG_WRITE",
            "protocol": "LOCAL_FILE",
            "outcome": "VIOLATION",
            "timestamp": (base_time + timedelta(minutes=5)).isoformat(),
            "raw_payload": "txn=99102 card=4111222233331234 cvv=932 exp=12/28 status=POST_AUTH_DEBUG",
            "agent_id": "AGT_PAY_GW",
            "source_id": "SRC_APP_GW",
            "cred_id": "CRED_GW_TLS_01",
            "exposes_elem": "ELEM_CVV",
        }
    )

    events.append(
        {
            "usage_id": "LOG_VIOLATION_02",
            "log_type": "network",
            "action": "API_POST",
            "protocol": "HTTP",
            "outcome": "VIOLATION",
            "timestamp": (base_time + timedelta(minutes=14)).isoformat(),
            "raw_payload": "POST http://analytics.internal.local/ingest pan=5500111122224444 batch=daily_settlement",
            "agent_id": "AGT_ANALYTICS_JOB",
            "source_id": "SRC_NET_IDS",
            "cred_id": "CRED_SYNC_SVC_02",
            "exposes_elem": "ELEM_PAN",
        }
    )

    events.append(
        {
            "usage_id": "LOG_VIOLATION_03",
            "log_type": "application",
            "action": "REPO_COMMIT_SCAN",
            "protocol": "HTTPS",
            "outcome": "VIOLATION",
            "timestamp": (base_time + timedelta(minutes=22)).isoformat(),
            "raw_payload": (
                "config_leak path=deploy/catalog_key.pem "
                "-----BEGIN RSA PRIVATE KEY-----MIIEpAIBAAKCAQEA7x9fakeKeyMaterial-----END RSA PRIVATE KEY-----"
            ),
            "agent_id": "AGT_CI_RUNNER",
            "source_id": "SRC_APP_GW",
            "cred_id": "CRED_CAT_PRIVKEY_99",
            "exposes_elem": "ELEM_PRIV_KEY",
        }
    )

    events.append(
        {
            "usage_id": "LOG_VIOLATION_04",
            "log_type": "access",
            "action": "CATALOG_METADATA_EXPORT",
            "protocol": "HTTPS",
            "outcome": "HIGH_RISK_ACCESS",
            "timestamp": (base_time + timedelta(minutes=31)).isoformat(),
            "raw_payload": "principal=CatalogMetadataSync key=CRED_CAT_PRIVKEY_99 scope=PII_LINEAGE_SCHEMA rows=1420",
            "agent_id": "AGT_CATALOG_CLIENT",
            "source_id": "SRC_ACC_CAT",
            "cred_id": "CRED_CAT_PRIVKEY_99",
            "exposes_elem": "ELEM_CATALOG_META",
        }
    )

    for idx in range(1, 11):
        events.append(
            {
                "usage_id": f"LOG_APP_{100 + idx}",
                "log_type": "application",
                "action": "AUTH_SUCCESS",
                "protocol": "HTTPS",
                "outcome": "COMPLIANT",
                "timestamp": (base_time + timedelta(minutes=35 + idx * 3)).isoformat(),
                "raw_payload": f"txn={20000 + rng.randint(100, 999)} card=****{rng.randint(1000, 9999)} token=tok_{idx:04d}",
                "agent_id": "AGT_PAY_GW",
                "source_id": "SRC_APP_GW",
                "cred_id": "CRED_GW_TLS_01",
                "exposes_elem": None,
            }
        )

    for idx in range(1, 10):
        events.append(
            {
                "usage_id": f"LOG_NET_{200 + idx}",
                "log_type": "network",
                "action": "TLS_SYNC_POST",
                "protocol": "HTTPS",
                "outcome": "COMPLIANT",
                "timestamp": (base_time + timedelta(minutes=70 + idx * 4)).isoformat(),
                "raw_payload": f"POST https://analytics.internal.local/ingest token=tok_net_{idx:04d} tls=1.3",
                "agent_id": "AGT_ANALYTICS_JOB",
                "source_id": "SRC_NET_IDS",
                "cred_id": "CRED_SYNC_SVC_02",
                "exposes_elem": None,
            }
        )

    for idx in range(1, 10):
        events.append(
            {
                "usage_id": f"LOG_ACC_{300 + idx}",
                "log_type": "access",
                "action": "CATALOG_READ_SCOPED",
                "protocol": "HTTPS",
                "outcome": "COMPLIANT",
                "timestamp": (base_time + timedelta(minutes=110 + idx * 5)).isoformat(),
                "raw_payload": f"principal=CatalogMetadataSync key=CRED_CAT_ROTATED_04 domain=PUBLIC_GLOSSARY query_id={idx}",
                "agent_id": "AGT_CATALOG_CLIENT",
                "source_id": "SRC_ACC_CAT",
                "cred_id": "CRED_CAT_ROTATED_04",
                "exposes_elem": None,
            }
        )

    for ev in events:
        ev["redacted_payload"] = redact_payload(ev.pop("raw_payload"))

    return events


# ---------------------------------------------------------------------------
# 5. Build Persistent Relate Store (omniguard.rl)
# ---------------------------------------------------------------------------
def seed_database() -> None:
    if DB_PATH.exists():
        if DB_PATH.is_dir():
            shutil.rmtree(DB_PATH)
        else:
            DB_PATH.unlink()

    db = relate.connect(str(DB_PATH))

    for fw in FRAMEWORKS:
        db.execute(
            "CREATE (:Framework {framework_id: $id, name: $name, domain: $domain})",
            fw,
        )

    for ctrl in CONTROLS:
        db.execute(
            """
            MATCH (f:Framework {framework_id: $framework_id})
            CREATE (c:Control {control_id: $id, code: $code, title: $title})
            CREATE (c)-[:BELONGS_TO]->(f)
            """,
            ctrl,
        )

    for elem in DATA_ELEMENTS:
        db.execute(
            """
            CREATE (:DataElement {
                elem_id: $id,
                name: $name,
                classification: $classification,
                is_sad: $is_sad
            })
            """,
            elem,
        )

    for pol in POLICIES:
        db.execute("CREATE (:Policy {policy_id: $id, name: $name})", pol)

    for rule in RULES:
        db.execute(
            """
            MATCH (p:Policy {policy_id: $policy_id}), (d:DataElement {elem_id: $protects_elem})
            CREATE (r:Rule {rule_id: $id, code: $code, description: $description})
            CREATE (p)-[:CONTAINS]->(r)
            CREATE (r)-[:PROTECTS]->(d)
            """,
            rule,
        )
        for ctrl_id in rule["maps_to_controls"]:
            db.execute(
                """
                MATCH (r:Rule {rule_id: $rule_id}), (c:Control {control_id: $ctrl_id})
                CREATE (r)-[:MAPS_TO]->(c)
                """,
                {"rule_id": rule["id"], "ctrl_id": ctrl_id},
            )

    for src in LOG_SOURCES:
        db.execute(
            """
            CREATE (:LogSource {
                source_id: $id,
                system_name: $system_name,
                collector: $collector,
                log_category: $log_category,
                zone: $zone
            })
            """,
            src,
        )

    for agt in AGENTS:
        db.execute(
            """
            CREATE (:Agent {
                agent_id: $id,
                name: $name,
                role: $role,
                network_zone: $network_zone
            })
            """,
            agt,
        )

    for cred in CREDENTIALS:
        db.execute(
            """
            CREATE (:Credential {
                cred_id: $id,
                cred_type: $cred_type,
                key_age_days: $key_age_days,
                max_age_days: $max_age_days,
                status: $status,
                allowed_targets: $allowed_targets
            })
            """,
            cred,
        )

    events = build_usage_events()
    for ev in events:
        db.execute(
            """
            MATCH (a:Agent {agent_id: $agent_id}),
                  (s:LogSource {source_id: $source_id}),
                  (k:Credential {cred_id: $cred_id})
            CREATE (u:Usage {
                usage_id: $usage_id,
                log_type: $log_type,
                action: $action,
                protocol: $protocol,
                outcome: $outcome,
                timestamp: $timestamp,
                redacted_payload: $redacted_payload
            })
            CREATE (a)-[:EMITTED]->(u)
            CREATE (s)-[:COLLECTED]->(u)
            CREATE (k)-[:AUTHENTICATED]->(u)
            """,
            ev,
        )
        if ev["exposes_elem"]:
            db.execute(
                """
                MATCH (u:Usage {usage_id: $usage_id}), (d:DataElement {elem_id: $exposes_elem})
                CREATE (u)-[:EXPOSES]->(d)
                """,
                ev,
            )

    counts = db.execute(
        """
        MATCH (u:Usage)
        RETURN u.log_type AS log_type, u.outcome AS outcome, count(u) AS events
        ORDER BY log_type, outcome
        """
    )
    print(f"Built {DB_PATH} successfully ({len(events)} total :Usage events):")
    for row in counts:
        print(f"  - {row['log_type']:11s} | {row['outcome']:16s} | {row['events']}")


if __name__ == "__main__":
    seed_database()

