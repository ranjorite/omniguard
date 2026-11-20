"""
OmniGuard — LangGraph Multi-Agent Compliance & Key-Risk Runner
Adapts LangGraph StateGraph + MemorySaver + Pydantic structured routing
over the in-process Relate graph store (`omniguard.rl`).

Requires: pip install langgraph pydantic relate-db
Optional (for LLM routing/rewriting): pip install langchain-openai + OPENAI_API_KEY
"""

from pathlib import Path
from typing import Any, Literal, TypedDict
import os
from pydantic import BaseModel, Field
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
import relate

DB_PATH = Path(__file__).resolve().parent / "omniguard.rl"


class RouteDecision(BaseModel):
    lenses: list[Literal["CDMC", "PCI_DSS", "NIST_800"]] = Field(
        description="Specialist compliance/risk lenses to invoke for this query"
    )
    standalone_query: str = Field(
        description="Query resolved with prior conversation context if needed"
    )
    reason: str = Field(description="Brief routing rationale")


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


class AuditState(TypedDict):
    user_query: str
    standalone_query: str
    active_lenses: list[str]
    route_reason: str
    total_usage_events: int
    evidence_rows: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    final_report: str


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
    return total_events, rows


def _route_query_decision(query: str) -> RouteDecision:
    q = query.lower()
    if os.getenv("OPENAI_API_KEY"):
        try:
            from langchain_openai import ChatOpenAI

            llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
            router_llm = llm.with_structured_output(RouteDecision)
            return router_llm.invoke(
                "Classify this compliance/security audit question into one or more lenses from "
                "['CDMC', 'PCI_DSS', 'NIST_800']. Use all three for broad/full audits or "
                "cross-framework questions. Query: " + query
            )
        except Exception:
            pass

    chosen: list[Literal["CDMC", "PCI_DSS", "NIST_800"]] = []
    if any(k in q for k in ["cdmc", "catalog", "lineage", "metadata", "classification"]):
        chosen.append("CDMC")
    if any(k in q for k in ["pci", "cvv", "pan", "sad", "cardholder", "transit", "http"]):
        chosen.append("PCI_DSS")
    if any(k in q for k in ["nist", "800", "key", "credential", "age", "exposed", "provenance", "collector", "log"]):
        chosen.append("NIST_800")

    if not chosen or "full" in q or "all" in q:
        chosen = ["CDMC", "PCI_DSS", "NIST_800"]

    return RouteDecision(
        lenses=chosen,
        standalone_query=query,
        reason=f"Routed to lenses {chosen} based on query intent.",
    )


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


def router_node(state: AuditState) -> dict[str, Any]:
    total_events, rows = _load_graph_evidence(DB_PATH)
    decision = _route_query_decision(state["user_query"])
    return {
        "total_usage_events": total_events,
        "evidence_rows": rows,
        "active_lenses": decision.lenses,
        "standalone_query": decision.standalone_query,
        "route_reason": decision.reason,
        "findings": [],
    }


def cdmc_node(state: AuditState) -> dict[str, Any]:
    if "CDMC" not in state["active_lenses"]:
        return {}
    cdmc_rows = [r for r in state["evidence_rows"] if r["framework"] == "CDMC"]
    if not cdmc_rows:
        return {}
    finding = SpecialistFinding(
        lens="CDMC",
        severity="HIGH",
        title="Data Classification, Pipeline Masking & Catalog Governance Gaps",
        summary=(
            f"Traced {len({r['usage_id'] for r in cdmc_rows})} CDMC-linked events across "
            "application, network, and access logs involving SAD/CHD exposure and catalog metadata access."
        ),
        remediation=(
            "Enforce pre-ingestion redaction/tokenization, restrict catalog lineage exports to "
            "scoped/non-exposed credentials, and maintain data classification tags."
        ),
        citations=_to_citations(cdmc_rows),
    )
    return {"findings": state["findings"] + [finding.model_dump()]}


def pci_dss_node(state: AuditState) -> dict[str, Any]:
    if "PCI_DSS" not in state["active_lenses"]:
        return {}
    pci_rows = [r for r in state["evidence_rows"] if r["framework"] == "PCI DSS v4.0.1"]
    if not pci_rows:
        return {}
    finding = SpecialistFinding(
        lens="PCI_DSS",
        severity="CRITICAL",
        title="Account Data & SAD Exposure Across Storage and Transit",
        summary=(
            f"Traced {len({r['usage_id'] for r in pci_rows})} PCI DSS v4.0.1 violation events "
            "covering post-authorization CVV logging and unencrypted HTTP PAN transmission."
        ),
        remediation=(
            "Eliminate SAD/CVV logging, scrub payloads prior to storage, and enforce TLS/HTTPS "
            "across all internal and external PAN transfer paths."
        ),
        citations=_to_citations(pci_rows),
    )
    return {"findings": state["findings"] + [finding.model_dump()]}


def nist_800_node(state: AuditState) -> dict[str, Any]:
    if "NIST_800" not in state["active_lenses"]:
        return {}
    nist_rows = [r for r in state["evidence_rows"] if str(r["framework"]).startswith("NIST SP 800")]
    if not nist_rows:
        return {}
    flagged_creds = {
        r["credential_id"]
        for r in nist_rows
        if r["credential_status"] != "active" or int(r["key_age_days"]) > int(r["max_age_days"])
    }
    flagged_traces = {
        r["usage_id"]
        for r in nist_rows
        if r["credential_status"] != "active" or int(r["key_age_days"]) > int(r["max_age_days"])
    }
    finding = SpecialistFinding(
        lens="NIST_800",
        severity="CRITICAL",
        title="Log Provenance, Cryptoperiod & Exposed Private Key Risk",
        summary=(
            f"Across {len({r['usage_id'] for r in nist_rows})} NIST SP 800 traces (800-53, 800-57, 800-92), "
            f"{len(flagged_creds)} exposed/over-aged credential ({', '.join(sorted(flagged_creds)) or 'none'}) "
            f"appears across {len(flagged_traces)} high-risk trace(s)."
        ),
        remediation=(
            "Revoke and rotate exposed/over-aged private keys immediately, enforce <=90-day "
            "cryptoperiods, and verify collector/source provenance across access, network, and application logs."
        ),
        citations=_to_citations(nist_rows),
    )
    return {"findings": state["findings"] + [finding.model_dump()]}


def synthesizer_node(state: AuditState) -> dict[str, Any]:
    lines = [
        f"Query      : {state['user_query']}",
        f"Route      : {state['active_lenses']} ({state['route_reason']})",
        f"Graph Store: {DB_PATH.name} ({state['total_usage_events']} total :Usage events)",
        "",
    ]
    for f_dict in state["findings"]:
        f = SpecialistFinding.model_validate(f_dict)
        lines.append(f"[{f.lens}] ({f.severity}) {f.title}")
        lines.append(f"  Summary     : {f.summary}")
        lines.append(f"  Remediation : {f.remediation}")
        lines.append(f"  Citations ({len(f.citations)}):")
        for c in f.citations:
            lines.append(
                f"    - {c.usage_id} [{c.log_type} @ {c.source_system}/{c.collector}] "
                f"| cred={c.credential_id} ({c.credential_status}, age={c.key_age_days}/{c.max_age_days}d) "
                f"| elem={c.data_element} | rule={c.rule_code} -> {c.control_code} ({c.framework})"
            )
        lines.append("")
    return {"final_report": "\n".join(lines).strip()}


def build_audit_graph():
    builder = StateGraph(AuditState)
    builder.add_node("router", router_node)
    builder.add_node("cdmc_agent", cdmc_node)
    builder.add_node("pci_dss_agent", pci_dss_node)
    builder.add_node("nist_800_agent", nist_800_node)
    builder.add_node("synthesizer", synthesizer_node)

    builder.add_edge(START, "router")
    builder.add_edge("router", "cdmc_agent")
    builder.add_edge("cdmc_agent", "pci_dss_agent")
    builder.add_edge("pci_dss_agent", "nist_800_agent")
    builder.add_edge("nist_800_agent", "synthesizer")
    builder.add_edge("synthesizer", END)

    return builder.compile(checkpointer=MemorySaver())


if __name__ == "__main__":
    app = build_audit_graph()
    config = {"configurable": {"thread_id": "omniguard-demo-1"}}

    out1 = app.invoke({"user_query": "Check exposed private keys and catalog metadata risks"}, config=config)
    print(out1["final_report"])
    print("-" * 72)
    out2 = app.invoke({"user_query": "Run full compliance audit across all frameworks"}, config=config)
    print(out2["final_report"])

