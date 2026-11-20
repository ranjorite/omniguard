"""
OmniGuard — In-Process Multi-Agent Compliance & Key-Risk Runner
Queries omniguard.rl in-process via `relate` (single process, zero file-lock contention)
and coordinates specialist lenses:
  - CDMC Specialist (data classification, lineage & catalog governance)
  - PCI DSS Specialist (SAD/CVV & PAN protection in storage/transit)
  - NIST SP 800 Specialist (log provenance/types via 800-92 & key lifecycle/exposure via 800-57/800-53)
  - Coordinator Agent (orchestrates evidence, deduplicates findings & emits cited report)

Requires: pip install relate-db pydantic
"""

from pathlib import Path
from typing import Any, Literal
from pydantic import BaseModel, Field
import relate

DB_PATH = Path(__file__).resolve().parent / "omniguard.rl"


class GraphCitation(BaseModel):
    usage_id: str
    log_type: str
    source_system: str
    collector: str
    credential_id: str
    credential_status: str
    key_age_days: int
    max_age_days: int
    data_element: str
    rule_code: str
    control_code: str
    framework: str


class SpecialistFinding(BaseModel):
    lens: Literal["CDMC", "PCI_DSS", "NIST_800"]
    severity: Literal["CRITICAL", "HIGH", "MEDIUM"]
    title: str
    summary: str
    remediation: str
    citations: list[GraphCitation] = Field(default_factory=list)


class AuditReport(BaseModel):
    database_path: str
    total_usage_events: int
    flagged_event_count: int
    findings: list[SpecialistFinding]
    coordinator_summary: str


def _rows_from_cursor(cursor: Any) -> list[dict[str, Any]]:
    """Normalizes a relate-db Cursor (or iterable of rows) into a list of dicts."""
    if cursor is None:
        return []
    cols = list(getattr(cursor, "columns", None) or getattr(cursor, "column_names", None) or [])
    results: list[dict[str, Any]] = []
    for row in cursor:
        if isinstance(row, dict):
            results.append(row)
        elif hasattr(row, "as_dict"):
            results.append(row.as_dict())
        elif cols and isinstance(row, (list, tuple)):
            results.append(dict(zip(cols, row)))
        elif hasattr(row, "keys") and hasattr(row, "__getitem__"):
            results.append({k: row[k] for k in row.keys()})
        else:
            results.append({"value": row})
    return results


def fetch_graph_evidence(db: Any) -> tuple[int, list[dict[str, Any]]]:
    total_rows = _rows_from_cursor(db.execute("MATCH (u:Usage) RETURN count(u) AS total"))
    total_events = int(total_rows[0].get("total", 0)) if total_rows else 0

    rows = _rows_from_cursor(
        db.execute(
            """
            MATCH (a:Agent)-[:EMITTED]->(u:Usage)-[:EXPOSES]->(d:DataElement)<-[:PROTECTS]-(r:Rule)<-[:CONTAINS]-(p:Policy)
            MATCH (s:LogSource)-[:COLLECTED]->(u)
            MATCH (k:Credential)-[:AUTHENTICATED]->(u)
            MATCH (r)-[:MAPS_TO]->(c:Control)-[:BELONGS_TO]->(f:Framework)
            RETURN
                u.usage_id AS usage_id,
                u.log_type AS log_type,
                u.action AS action,
                u.protocol AS protocol,
                u.outcome AS outcome,
                u.redacted_payload AS redacted_payload,
                a.name AS agent_name,
                s.system_name AS source_system,
                s.collector AS collector,
                s.zone AS source_zone,
                k.cred_id AS credential_id,
                k.cred_type AS cred_type,
                k.status AS credential_status,
                k.key_age_days AS key_age_days,
                k.max_age_days AS max_age_days,
                d.name AS data_element,
                d.classification AS classification,
                r.code AS rule_code,
                c.code AS control_code,
                f.name AS framework
            ORDER BY u.usage_id, f.name, c.code
            """
        )
    )
    return total_events, rows


def _to_citations(rows: list[dict[str, Any]]) -> list[GraphCitation]:
    seen = set()
    citations: list[GraphCitation] = []
    for r in rows:
        key = (
            r["usage_id"],
            r["credential_id"],
            r["rule_code"],
            r["control_code"],
            r["framework"],
        )
        if key in seen:
            continue
        seen.add(key)
        citations.append(
            GraphCitation(
                usage_id=str(r["usage_id"]),
                log_type=str(r["log_type"]),
                source_system=str(r["source_system"]),
                collector=str(r["collector"]),
                credential_id=str(r["credential_id"]),
                credential_status=str(r["credential_status"]),
                key_age_days=int(r["key_age_days"]),
                max_age_days=int(r["max_age_days"]),
                data_element=str(r["data_element"]),
                rule_code=str(r["rule_code"]),
                control_code=str(r["control_code"]),
                framework=str(r["framework"]),
            )
        )
    return citations


def cdmc_agent(rows: list[dict[str, Any]]) -> list[SpecialistFinding]:
    cdmc_rows = [r for r in rows if r["framework"] == "CDMC"]
    findings: list[SpecialistFinding] = []
    if cdmc_rows:
        findings.append(
            SpecialistFinding(
                lens="CDMC",
                severity="HIGH",
                title="Data Classification, Pipeline Masking & Catalog Governance Gaps",
                summary=(
                    f"Detected {len({r['usage_id'] for r in cdmc_rows})} CDMC-linked events across "
                    "application, network, and access telemetry involving SAD/CHD exposure and "
                    "sensitive catalog/lineage metadata access."
                ),
                remediation=(
                    "Enforce pre-ingestion redaction/tokenization in pipelines, restrict catalog lineage "
                    "exports to scoped/non-exposed credentials, and verify data element classifications."
                ),
                citations=_to_citations(cdmc_rows),
            )
        )
    return findings


def pci_dss_agent(rows: list[dict[str, Any]]) -> list[SpecialistFinding]:
    pci_rows = [r for r in rows if r["framework"] == "PCI DSS v4.0.1"]
    findings: list[SpecialistFinding] = []
    if pci_rows:
        findings.append(
            SpecialistFinding(
                lens="PCI_DSS",
                severity="CRITICAL",
                title="Account Data & SAD Exposure Across Storage and Transit",
                summary=(
                    f"Detected {len({r['usage_id'] for r in pci_rows})} PCI DSS v4.0.1 violation traces "
                    "covering post-authorization CVV logging and unencrypted HTTP PAN transmission."
                ),
                remediation=(
                    "Disable SAD/CVV logging immediately, scrub/redact payloads before storage, and "
                    "enforce TLS/HTTPS across all internal and external PAN transfer paths."
                ),
                citations=_to_citations(pci_rows),
            )
        )
    return findings


def nist_800_agent(rows: list[dict[str, Any]]) -> list[SpecialistFinding]:
    nist_rows = [r for r in rows if str(r["framework"]).startswith("NIST SP 800")]
    findings: list[SpecialistFinding] = []
    if nist_rows:
        exposed_or_aged = [
            r
            for r in nist_rows
            if r["credential_status"] != "active"
            or int(r["key_age_days"]) > int(r["max_age_days"])
        ]
        findings.append(
            SpecialistFinding(
                lens="NIST_800",
                severity="CRITICAL",
                title="Log Provenance, Cryptoperiod & Exposed Private Key Risk",
                summary=(
                    f"Across {len({r['usage_id'] for r in nist_rows})} NIST SP 800 traces (800-53, 800-57, 800-92), "
                    f"{len({r['credential_id'] for r in exposed_or_aged})} credential trace(s) show non-active/exposed "
                    "status or key age exceeding the 90-day cryptoperiod."
                ),
                remediation=(
                    "Revoke and rotate exposed/over-aged private keys immediately, enforce <=90-day "
                    "cryptoperiods, and maintain collector/source provenance across access, network, and application logs."
                ),
                citations=_to_citations(nist_rows),
            )
        )
    return findings


def coordinator_agent(db_path: Path = DB_PATH) -> AuditReport:
    if not db_path.exists():
        raise FileNotFoundError(f"Relate store not found at {db_path}. Run seed_graph.py first.")

    db = relate.connect(str(db_path))
    total_events, rows = fetch_graph_evidence(db)

    findings: list[SpecialistFinding] = []
    findings.extend(cdmc_agent(rows))
    findings.extend(pci_dss_agent(rows))
    findings.extend(nist_800_agent(rows))

    flagged_ids = {r["usage_id"] for r in rows}
    summary = (
        f"Coordinator audited {total_events} total :Usage events in {db_path.name} and traced "
        f"{len(flagged_ids)} high-risk/violation events across {len(findings)} specialist lenses "
        "(CDMC, PCI DSS v4.0.1, NIST SP 800-53/57/92) with zero raw SAD or key material stored."
    )

    return AuditReport(
        database_path=str(db_path),
        total_usage_events=total_events,
        flagged_event_count=len(flagged_ids),
        findings=findings,
        coordinator_summary=summary,
    )


def print_report(report: AuditReport) -> None:
    print("=" * 72)
    print("OMNIGUARD MULTI-AGENT COMPLIANCE & RISK REPORT")
    print("=" * 72)
    print(report.coordinator_summary)
    print()
    for f in report.findings:
        print(f"[{f.lens}] ({f.severity}) {f.title}")
        print(f"  Summary     : {f.summary}")
        print(f"  Remediation : {f.remediation}")
        print(f"  Citations ({len(f.citations)}):")
        for c in f.citations:
            print(
                f"    - {c.usage_id} [{c.log_type} @ {c.source_system}/{c.collector}] "
                f"| cred={c.credential_id} ({c.credential_status}, age={c.key_age_days}/{c.max_age_days}d) "
                f"| elem={c.data_element} | rule={c.rule_code} -> {c.control_code} ({c.framework})"
            )
        print()


if __name__ == "__main__":
    report = coordinator_agent()
    print_report(report)
