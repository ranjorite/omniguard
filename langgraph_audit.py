"""
OmniGuard - Natural-Language LangGraph Compliance & Key-Risk Runner
Handles open-ended natural-language queries and follow-up turns over `omniguard.rl`
using LangGraph StateGraph + MemorySaver + Pydantic structured models.

Requires: pip install langgraph pydantic relate-db
Optional (for LLM intent parsing/synthesis): pip install langchain-openai + OPENAI_API_KEY
"""

from pathlib import Path
import os
import re
from typing import Any, Literal, TypedDict
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, Field
import relate

DB_PATH = Path(__file__).resolve().parent / "omniguard.rl"


class QueryPlan(BaseModel):
    standalone_query: str = Field(
        description="Natural-language query resolved with prior conversation context"
    )
    lenses: list[Literal["CDMC", "PCI_DSS", "NIST_800", "OWASP"]] = Field(
        description="Relevant compliance/risk lenses for the question"
    )
    log_type: Literal["access", "network", "application"] | None = Field(
        default=None, description="Optional log category filter if the user asked about one"
    )
    only_risky_credentials: bool = Field(
        default=False, description="True when user asks about exposed, leaked, or over-aged keys/credentials"
    )
    min_key_age_days: int | None = Field(
        default=None, description="Optional minimum key age threshold mentioned by the user"
    )
    data_element_keyword: str | None = Field(
        default=None, description="Optional data element focus such as CVV, PAN, KEY, or CATALOG"
    )
    source_system_keyword: str | None = Field(
        default=None, description="Optional source system focus such as STAGING, PAYMENT, CATALOG, or SENSOR"
    )
    reason: str = Field(description="Concise explanation of how the query was interpreted")


class GraphCitation(BaseModel):
    usage_id: str
    log_type: str
    protocol: str
    action: str
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
    lens: Literal["CDMC", "PCI_DSS", "NIST_800", "OWASP"]
    severity: Literal["CRITICAL", "HIGH", "MEDIUM"]
    title: str
    summary: str
    remediation: str
    citations: list[GraphCitation] = Field(default_factory=list)


class AuditState(TypedDict):
    user_query: str
    history: list[dict[str, str]]
    standalone_query: str
    plan: dict[str, Any]
    active_lenses: list[str]
    total_usage_events: int
    evidence_rows: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    final_report: str


ONTOLOGY_SPEC = """
OmniGuard Graph Ontology (omniguard.rl):
Nodes:
  - :Agent (name, role, network_zone)
  - :Usage (usage_id, log_type [application|network|access], action, protocol, outcome, redacted_payload)
  - :LogSource (source_id, system_name, collector, log_category, zone)
  - :Credential (cred_id, cred_type, key_age_days, max_age_days, status [active|exposed], allowed_targets)
  - :DataElement (elem_id, name [CVV|PAN|PRIVATE_SIGNING_KEY|CATALOG_LINEAGE_METADATA], classification, is_sad)
  - :Rule (rule_id, code, description)
  - :Policy (policy_id, name)
  - :Control (control_id, code, title)
  - :Framework (framework_id, name [PCI DSS v4.0.1|CDMC|NIST SP 800-53|NIST SP 800-57|NIST SP 800-92])

Relationships:
  (:Agent)-[:EMITTED]->(:Usage)
  (:LogSource)-[:COLLECTED]->(:Usage)
  (:Credential)-[:AUTHENTICATED]->(:Usage)
  (:Usage)-[:EXPOSES]->(:DataElement)
  (:Rule)-[:PROTECTS]->(:DataElement)
  (:Policy)-[:CONTAINS]->(:Rule)
  (:Rule)-[:MAPS_TO]->(:Control)-[:BELONGS_TO]->(:Framework)
"""


def _synthesize_grounded_answer(
    lens: str,
    user_query: str,
    citations: list[GraphCitation],
    fallback_summary: str,
) -> str:
    """Uses LLM grounded strictly in retrieved graph citations when OPENAI_API_KEY is set."""
    if not os.getenv("OPENAI_API_KEY") or not citations:
        return fallback_summary
    try:
        from langchain_openai import ChatOpenAI

        llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
        evidence_lines = [
            f"- usage_id={c.usage_id}, log_type={c.log_type}, protocol={c.protocol}, action={c.action}, "
            f"source={c.source_system}/{c.collector}, cred={c.credential_id} (status={c.credential_status}, "
            f"age={c.key_age_days}/{c.max_age_days}d), element={c.data_element}, rule={c.rule_code}, "
            f"control={c.control_code}, framework={c.framework}"
            for c in citations
        ]
        prompt = (
            f"You are the {lens} compliance specialist for OmniGuard.\n"
            f"Answer the user's question concisely using ONLY the graph evidence below.\n"
            f"Explicitly reference the relevant usage_id, credential_id, control_code, and framework.\n"
            f"Do not assume or invent anything not present in the evidence.\n\n"
            f"Question: {user_query}\n"
            f"Graph Evidence:\n" + "\n".join(evidence_lines)
        )
        resp = llm.invoke(prompt)
        text = getattr(resp, "content", "") or ""
        return text.strip() or fallback_summary
    except Exception:
        return fallback_summary


def _rows_from_cursor(cursor: Any) -> list[dict[str, Any]]:
    if cursor is None:
        return []
    cols = list(getattr(cursor, "columns", None) or getattr(cursor, "column_names", None) or [])
    out: list[dict[str, Any]] = []
    for row in cursor:
        if isinstance(row, dict):
            out.append(row)
        elif hasattr(row, "as_dict"):
            out.append(row.as_dict())
        elif cols and isinstance(row, (list, tuple)):
            out.append(dict(zip(cols, row)))
        elif hasattr(row, "keys") and hasattr(row, "__getitem__"):
            out.append({k: row[k] for k in row.keys()})
        else:
            out.append({"value": row})
    return out


def _resolve_standalone_query(query: str, history: list[dict[str, str]]) -> str:
    """Resolves follow-up pronouns/references using prior turns in the session."""
    q = query.strip()
    follow_up_markers = [
        "that ", "those ", "same ", "it ", "them ", "what about", "which collector",
        "which log", "how old", "who did", "why did"
    ]
    if history and any(m in q.lower() for m in follow_up_markers):
        last_user = next((h["content"] for h in reversed(history) if h["role"] == "user"), "")
        if last_user and last_user.lower() != q.lower():
            return f"{q} (Context from previous question: {last_user})"
    return q


def _build_query_plan(standalone_query: str) -> QueryPlan:
    """Interprets open-ended natural language into lenses + graph filters."""
    if os.getenv("OPENAI_API_KEY"):
        try:
            from langchain_openai import ChatOpenAI

            llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
            planner = llm.with_structured_output(QueryPlan)
            return planner.invoke(
                ONTOLOGY_SPEC
                + "\nMap this natural-language security/governance question to a QueryPlan over "
                + "lenses ['CDMC', 'PCI_DSS', 'NIST_800', 'OWASP'] and filters (log_type: access|network|application, "
                + "only_risky_credentials, min_key_age_days, data_element_keyword, source_system_keyword). "
                + "Set filters ONLY for what this specific question asks about. "
                + f"Question: {standalone_query}"
            )
        except Exception:
            pass

    ql = standalone_query.lower()

    log_type: Literal["access", "network", "application"] | None = None
    if any(w in ql for w in ["network", "http", "https", "tls", "wire", "transit", "packet"]):
        log_type = "network"
    elif any(w in ql for w in ["access", "login", "auth", "principal", "export"]):
        log_type = "access"
    elif any(w in ql for w in ["app", "application", "debug", "repo", "commit", "code"]):
        log_type = "application"

    age_match = re.search(r"(?:over|older than|more than|above|>)\s*(\d+)\s*days?", ql)
    min_key_age_days = int(age_match.group(1)) if age_match else None

    only_risky_credentials = any(
        w in ql for w in ["exposed", "key", "keys", "credential", "expired", "aged", "rotation", "revok"]
    )

    kws: list[str] = []
    if "cvv" in ql or "sad" in ql or "security code" in ql:
        kws.append("CVV")
    if "pan" in ql or "card" in ql or "cardholder" in ql or "unencrypted" in ql or "http" in ql:
        kws.append("PAN")
    if "catalog" in ql or "lineage" in ql or "metadata" in ql:
        kws.append("CATALOG")
    if "private" in ql or "signing" in ql or "key" in ql:
        kws.append("KEY")
    data_element_keyword: str | None = ",".join(dict.fromkeys(kws)) if kws else None

    lenses: list[Literal["CDMC", "PCI_DSS", "NIST_800", "OWASP"]] = []
    if any(w in ql for w in ["cdmc", "catalog", "lineage", "metadata", "classif", "govern", "mask", "pii", "export", "bulk"]):
        lenses.append("CDMC")
    if any(w in ql for w in ["owasp", "staging", "portal", "hardcoded", "debug", "html", "breach", "misconfig"]):
        lenses.append("OWASP")
    source_system_keyword: str | None = None
    if "staging" in ql or "portal" in ql:
        source_system_keyword = "STAGING"
    elif "payment" in ql:
        source_system_keyword = "PAYMENT"
    elif "sensor" in ql:
        source_system_keyword = "SENSOR"
    if any(w in ql for w in ["pci", "cvv", "pan", "sad", "card", "encrypt", "http", "transit", "payment"]):
        lenses.append("PCI_DSS")
    if any(w in ql for w in ["nist", "800", "key", "keys", "credential", "age", "aged", "exposed", "collector", "source", "provenance", "audit log"]):
        lenses.append("NIST_800")

    if not lenses:
        lenses = ["CDMC", "PCI_DSS", "NIST_800"]

    return QueryPlan(
        standalone_query=standalone_query,
        lenses=lenses,
        log_type=log_type,
        only_risky_credentials=only_risky_credentials,
        min_key_age_days=min_key_age_days,
        data_element_keyword=data_element_keyword,
        source_system_keyword=source_system_keyword,
        reason=f"Natural-language plan -> lenses={lenses}, log_type={log_type}, risky_creds={only_risky_credentials}, min_age={min_key_age_days}, elem={data_element_keyword}, src={source_system_keyword}",
    )


def _load_graph_evidence(db_path: Path = DB_PATH) -> tuple[int, list[dict[str, Any]]]:
    if not db_path.exists():
        raise FileNotFoundError(f"Relate store not found at {db_path}. Run seed_graph.py first.")
    db = relate.connect(str(db_path))
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
    causal_rows = _rows_from_cursor(
        db.execute("MATCH (u1:Usage)-[:ENABLED]->(u2:Usage) RETURN u1.usage_id AS src_id, u2.usage_id AS dst_id")
    )
    enabled_by_map: dict[str, list[str]] = {}
    enables_map: dict[str, list[str]] = {}
    for cr in causal_rows:
        s_id = str(cr.get("src_id", ""))
        d_id = str(cr.get("dst_id", ""))
        enabled_by_map.setdefault(d_id, []).append(s_id)
        enables_map.setdefault(s_id, []).append(d_id)
    for r in rows:
        uid = str(r.get("usage_id", ""))
        r["enabled_by"] = enabled_by_map.get(uid, [])
        r["enables"] = enables_map.get(uid, [])
    return total_events, rows


def _apply_plan_filters(rows: list[dict[str, Any]], plan: QueryPlan) -> list[dict[str, Any]]:
    filtered = list(rows)
    if plan.source_system_keyword:
        src_kw = plan.source_system_keyword.strip().upper()
        by_src = [r for r in filtered if src_kw in str(r.get("source_system", "")).upper()]
        if by_src:
            filtered = by_src
    if plan.log_type:
        by_type = [r for r in filtered if str(r.get("log_type")) == plan.log_type]
        if by_type:
            filtered = by_type
    if plan.min_key_age_days is not None:
        by_age = [r for r in filtered if int(r.get("key_age_days", 0)) >= plan.min_key_age_days]
        if by_age:
            filtered = by_age
    if plan.only_risky_credentials:
        by_cred = [
            r
            for r in filtered
            if str(r.get("credential_status")) != "active"
            or int(r.get("key_age_days", 0)) > int(r.get("max_age_days", 90))
        ]
        if by_cred:
            filtered = by_cred
    if plan.data_element_keyword:
        terms = [t.strip().upper() for t in plan.data_element_keyword.split(",") if t.strip()]
        by_elem = [
            r
            for r in filtered
            if any(t in str(r.get("data_element", "")).upper() for t in terms)
            or ("PAN" in terms and str(r.get("protocol", "")).upper() == "HTTP")
        ]
        filtered = by_elem
    # Causal kill-chain expansion: include upstream :Usage events that ENABLED matched violations
    matched_ids = {str(r.get("usage_id", "")) for r in filtered}
    linked_ids: set[str] = set()
    for r in filtered:
        for rel_id in r.get("enabled_by", []) + r.get("enables", []):
            if rel_id not in matched_ids:
                linked_ids.add(rel_id)
    if linked_ids:
        existing_keys = {(r.get("usage_id"), r.get("control_code")) for r in filtered}
        for r in rows:
            if str(r.get("usage_id", "")) in linked_ids:
                k = (r.get("usage_id"), r.get("control_code"))
                if k not in existing_keys:
                    filtered.append(r)
                    existing_keys.add(k)
    return filtered


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
                protocol=str(r["protocol"]),
                action=str(r["action"]),
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


def router_node(state: AuditState) -> dict[str, Any]:
    total_events, rows = _load_graph_evidence(DB_PATH)
    standalone = _resolve_standalone_query(state["user_query"], state.get("history", []))
    plan = _build_query_plan(state["user_query"])
    plan.standalone_query = standalone
    matched_rows = _apply_plan_filters(rows, plan)
    return {
        "total_usage_events": total_events,
        "standalone_query": standalone,
        "plan": plan.model_dump(),
        "active_lenses": plan.lenses,
        "evidence_rows": matched_rows,
        "findings": [],
    }


def cdmc_node(state: AuditState) -> dict[str, Any]:
    if "CDMC" not in state["active_lenses"]:
        return {}
    cdmc_rows = [r for r in state["evidence_rows"] if r["framework"] == "CDMC"]
    if not cdmc_rows:
        return {}
    cites = _to_citations(cdmc_rows)
    cdmc_fallback = (
        f"Matched {len({c.usage_id for c in cites})} event(s) for \"{state['user_query']}\" "
        f"across collectors {', '.join(sorted({c.collector for c in cites}))} involving "
        f"{', '.join(sorted({c.data_element for c in cites}))}."
    )
    finding = SpecialistFinding(
        lens="CDMC",
        severity="HIGH",
        title="Data Classification, Pipeline Masking & Catalog Governance",
        summary=_synthesize_grounded_answer("CDMC", state["user_query"], cites, cdmc_fallback),
        remediation=(
            "Keep payloads scrubbed/tokenized before ingestion, restrict catalog lineage exports "
            "to non-exposed/scoped keys, and enforce classification tags."
        ),
        citations=cites,
    )
    return {"findings": state["findings"] + [finding.model_dump()]}


def pci_dss_node(state: AuditState) -> dict[str, Any]:
    if "PCI_DSS" not in state["active_lenses"]:
        return {}
    pci_rows = [r for r in state["evidence_rows"] if r["framework"] == "PCI DSS v4.0.1"]
    if not pci_rows:
        return {}
    cites = _to_citations(pci_rows)
    pci_fallback = (
        f"Matched {len({c.usage_id for c in cites})} PCI DSS v4.0.1 trace(s) for \"{state['user_query']}\" "
        f"covering {', '.join(sorted({c.data_element for c in cites}))} over "
        f"{', '.join(sorted({c.protocol for c in cites}))}."
    )
    finding = SpecialistFinding(
        lens="PCI_DSS",
        severity="CRITICAL",
        title="Account Data & SAD Protection (Storage & Transit)",
        summary=_synthesize_grounded_answer("PCI_DSS", state["user_query"], cites, pci_fallback),
        remediation=(
            "Prevent post-authorization SAD/CVV logging, scrub sensitive values before persistence, "
            "and enforce encrypted transport (HTTPS/TLS) for PAN."
        ),
        citations=cites,
    )
    return {"findings": state["findings"] + [finding.model_dump()]}


def nist_800_node(state: AuditState) -> dict[str, Any]:
    if "NIST_800" not in state["active_lenses"]:
        return {}
    nist_rows = [r for r in state["evidence_rows"] if str(r["framework"]).startswith("NIST SP 800")]
    if not nist_rows:
        return {}
    cites = _to_citations(nist_rows)
    flagged_creds = sorted(
        {
            c.credential_id
            for c in cites
            if c.credential_status != "active" or c.key_age_days > c.max_age_days
        }
    )
    nist_fallback = (
        f"Matched {len({c.usage_id for c in cites})} NIST SP 800 trace(s) for \"{state['user_query']}\" "
        f"from {', '.join(sorted({c.source_system for c in cites}))}; flagged credentials: "
        f"{', '.join(flagged_creds) if flagged_creds else 'none in filtered subset'}."
    )
    finding = SpecialistFinding(
        lens="NIST_800",
        severity="CRITICAL",
        title="Log Provenance, Key Lifecycle & Access Controls (SP 800-53 / 800-57 / 800-92)",
        summary=_synthesize_grounded_answer("NIST_800", state["user_query"], cites, nist_fallback),
        remediation=(
            "Revoke and rotate exposed or >90-day keys immediately and preserve collector/source "
            "provenance across access, network, and application logs."
        ),
        citations=cites,
    )
    return {"findings": state["findings"] + [finding.model_dump()]}


def owasp_node(state: AuditState) -> dict[str, Any]:
    plan = QueryPlan.model_validate(state["plan"])
    if "OWASP" not in plan.lenses:
        return {}
    matched = [r for r in state["evidence_rows"] if "OWASP" in str(r.get("framework", "")).upper()]
    if not matched:
        return {}
    citations = _to_citations(matched)
    systems = sorted({c.source_system for c in citations})
    controls = sorted({c.control_code for c in citations})
    fallback_text = (
        f"Matched {len(citations)} OWASP Top 10 finding(s) for '{plan.standalone_query}' "
        f"on {', '.join(systems)} ({', '.join(controls)})."
    )
    summary = _synthesize_grounded_answer(lens="OWASP", user_query=plan.standalone_query, citations=citations, fallback_summary=fallback_text)
    finding = SpecialistFinding(
        lens="OWASP",
        severity="CRITICAL",
        title="Application Security Misconfiguration & Embedded Secrets (OWASP Top 10:2025)",
        summary=summary,
        remediation="Remove hardcoded tokens/debug endpoints from public HTML/JS, enforce CI/CD secret scanning, and restrict staging access.",
        citations=citations,
    )
    return {"findings": list(state.get("findings", [])) + [finding.model_dump()]}



CONTROL_EXPLANATIONS: dict[str, str] = {
    "OWASP-2025-A02": "Security Misconfiguration ? hardcoded secrets or debug endpoints left in public web code",
    "NIST-800-53-IA-5(7)": "No Embedded Static Authenticators ? passwords/tokens must never be hardcoded in source or HTML",
    "NIST-800-53-IA-5": "Authenticator Management ? compromised or expired (>90-day) credentials must be revoked and rotated",
    "NIST-800-53-AU-2": "Event Logging Governance ? sensitive authentication data (like CVV) must never be written to logs",
    "NIST-800-53-SC-8": "Transmission Confidentiality ? sensitive data must be encrypted in transit (HTTPS/TLS, not plain HTTP)",
    "NIST-800-57-P1": "Cryptographic Key Lifecycle ? private signing keys must not be exposed or exceed rotation limits",
    "NIST-800-92-S3": "Log Management & Provenance ? audit logs must preserve verified collector and source-system attribution",
    "CDMC-04": "Cloud Data Protection & Export Governance ? restricted PII and catalog metadata must be protected from unauthorized bulk export",
    "CDMC-09": "Sensitive Data Scrubbing & Masking ? regulated fields (CVV/PAN) must be masked before storage or transit",
    "PCI-3.3.1.2": "No Post-Auth CVV Storage ? card security codes (CVV/CVC) must never be stored in files or logs after authorization",
    "PCI-4.2.1": "Strong Cryptography in Transit ? cardholder numbers (PAN) must never travel over unencrypted HTTP",
}


def _build_human_report(state: AuditState, plan: QueryPlan) -> str:
    findings = [SpecialistFinding.model_validate(f) for f in state.get("findings", [])]
    if not findings:
        return (
            "Executive Summary:\n"
            "  No security or compliance violations were found matching your question.\n"
        )

    # Deduplicate citations by (usage_id, control_code)
    all_citations: list[GraphCitation] = []
    seen_cit: set[tuple[str, str]] = set()
    for f in findings:
        for c in f.citations:
            key = (c.usage_id, c.control_code)
            if key not in seen_cit:
                seen_cit.add(key)
                all_citations.append(c)

    systems = sorted({c.source_system for c in all_citations})
    collectors = sorted({c.collector for c in all_citations})
    elements = sorted({c.data_element for c in all_citations})
    risky_creds = sorted({
        f"{c.credential_id} ({c.credential_status}, {c.key_age_days}d old vs {c.max_age_days}d policy)"
        for c in all_citations
        if c.credential_status != "active" or c.key_age_days > c.max_age_days
    })

    # Detect causal kill-chain links from evidence_rows
    chains: list[str] = []
    seen_chains: set[tuple[str, str]] = set()
    for r in state.get("evidence_rows", []):
        u_id = str(r.get("usage_id", ""))
        for dst in r.get("enables", []):
            if (u_id, dst) not in seen_chains:
                seen_chains.add((u_id, dst))
                chains.append(
                    f"{u_id} (root-cause credential leak) directly enabled {dst} (unauthorized bulk data export)"
                )

    ql = state["user_query"].lower()
    is_priority_q = any(w in ql for w in ["priorit", "first", "remediat", "fix first"])

    lines: list[str] = []
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 72)
    if is_priority_q:
        lines.append(
            f"Your team has {len({c.usage_id for c in all_citations})} active risk event(s) across "
            f"{', '.join(systems)}. Address the Critical credential/exposure items first before routine hardening."
        )
    else:
        lines.append(
            f"Yes ? OmniGuard flagged {len({c.usage_id for c in all_citations})} security/compliance event(s) "
            f"on {', '.join(systems)} (captured by {', '.join(collectors)}) involving {', '.join(elements)}."
        )
        if risky_creds:
            lines.append(f"Compromised / Over-Aged Credentials: {'; '.join(risky_creds)}.")
        if chains:
            lines.append(f"Attack Chain (Root Cause -> Impact): {'; '.join(chains)}.")

    lines.append("")
    lines.append("WHAT THIS MEANS (PLAIN-ENGLISH COMPLIANCE IMPACT)")
    lines.append("-" * 72)
    seen_ctrl: set[str] = set()
    for c in all_citations:
        if c.control_code in seen_ctrl:
            continue
        seen_ctrl.add(c.control_code)
        meaning = CONTROL_EXPLANATIONS.get(c.control_code, f"{c.framework} control violation")
        lines.append(f"  * {c.control_code} ({c.framework}): {meaning}.")

    lines.append("")
    lines.append("PRIORITIZED RECOMMENDED ACTIONS")
    lines.append("-" * 72)
    sev_rank = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}
    ranked_findings = sorted(findings, key=lambda x: sev_rank.get(x.severity.upper(), 9))
    seen_rem: set[str] = set()
    step = 1
    for f in ranked_findings:
        if f.remediation not in seen_rem:
            seen_rem.add(f.remediation)
            lines.append(f"  P{step} [{f.severity} - {f.lens}]: {f.remediation}")
            step += 1

    lines.append("")
    lines.append(f"AUDIT EVIDENCE TRAIL ({DB_PATH.name} | {state['total_usage_events']} total events scanned)")
    lines.append("-" * 72)
    for c in all_citations:
        lines.append(
            f"  - {c.usage_id} on {c.source_system} (via {c.collector}, {c.log_type}/{c.protocol}) | "
            f"Data: {c.data_element} | Cred: {c.credential_id} ({c.credential_status}, {c.key_age_days}/{c.max_age_days}d) | "
            f"Control: {c.control_code}"
        )

    return "\n".join(lines)


def synthesizer_node(state: AuditState) -> dict[str, Any]:
    plan = QueryPlan.model_validate(state["plan"])
    report = _build_human_report(state, plan)
    updated_history = list(state.get("history", [])) + [
        {"role": "user", "content": state["user_query"]},
        {"role": "assistant", "content": report},
    ]
    return {"final_report": report, "history": updated_history}


def build_audit_graph():
    builder = StateGraph(AuditState)
    builder.add_node("router", router_node)
    builder.add_node("cdmc_agent", cdmc_node)
    builder.add_node("pci_dss_agent", pci_dss_node)
    builder.add_node("nist_800_agent", nist_800_node)
    builder.add_node("owasp_agent", owasp_node)
    builder.add_node("synthesizer", synthesizer_node)

    builder.add_edge(START, "router")
    builder.add_edge("router", "cdmc_agent")
    builder.add_edge("cdmc_agent", "pci_dss_agent")
    builder.add_edge("pci_dss_agent", "nist_800_agent")
    builder.add_edge("nist_800_agent", "owasp_agent")
    builder.add_edge("owasp_agent", "synthesizer")
    builder.add_edge("synthesizer", END)

    return builder.compile(checkpointer=MemorySaver())


def run_chat_loop(thread_id: str = "omniguard-chat-1") -> None:
    app = build_audit_graph()
    config = {"configurable": {"thread_id": thread_id}}
    print("OmniGuard Natural-Language Assistant (type 'exit' or 'quit' to stop)")
    print("-" * 72)
    while True:
        try:
            q = input("\nAsk a compliance/risk question: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting chat.")
            break
        if not q:
            continue
        if q.lower() in {"exit", "quit"}:
            print("Exiting chat.")
            break
        snap = app.get_state(config)
        hist = snap.values.get("history", []) if snap and snap.values else []
        out = app.invoke({"user_query": q, "history": hist}, config=config)
        print("\n" + out["final_report"])


if __name__ == "__main__":
    import sys

    if "--chat" in sys.argv:
        run_chat_loop()
    else:
        app = build_audit_graph()
        config = {"configurable": {"thread_id": "omniguard-nl-demo"}}
        prompts = [
            "Did any old private keys over 90 days touch catalog lineage metadata?",
            "What about unencrypted card traffic or CVV leaks?",
        ]
        for p in prompts:
            snap = app.get_state(config)
            hist = snap.values.get("history", []) if snap and snap.values else []
            res = app.invoke({"user_query": p, "history": hist}, config=config)
            print(res["final_report"])
            print("-" * 72)

