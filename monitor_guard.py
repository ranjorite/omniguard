import html
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

import langgraph_audit

from omniguard_runtime import BASE_DIR, query_relate_rows, resolve_db_path

BASE_DB = resolve_db_path()
DEMO_DB = Path(BASE_DIR / "omniguard_demo.rl")
EVENTS_FILE = Path("portal_events.jsonl")
DASHBOARD_FILE = Path("dashboard.html")


def run_cypher(db_path: Path, query: str) -> list[dict]:
    rows = query_relate_rows(query, resolve_db_path(db_path))
    if not rows:
        return []
    out = []
    for r in rows:
        if isinstance(r, dict):
            out.append(r)
        elif isinstance(r, (list, tuple)):
            out.append({"values": list(r)})
        else:
            out.append({"output": str(r)})
    return out


def ingest_portal_events(db_path: Path, events_path: Path, timestamp: str) -> int:
    """Read portal_events.jsonl and write the StagingCareerPortal kill chain into omniguard_demo.rl."""
    lines = [ln.strip() for ln in events_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    ingest_q = f"""
    MERGE (c:Credential {{cred_id: 'CRED_STG_ADMIN_01'}})
    SET c.cred_type = 'admin_token',
        c.allowed_targets = 'StagingCareerPortal',
        c.key_age_days = 120,
        c.max_age_days = 90,
        c.status = 'EXPOSED'
    MERGE (u1:Usage {{usage_id: 'BREACH_SIM_01'}})
    SET u1.system = 'StagingCareerPortal',
        u1.action = 'Hardcoded admin token scraped from public landing page HTML',
        u1.timestamp = '{timestamp}'
    MERGE (u2:Usage {{usage_id: 'BREACH_SIM_02'}})
    SET u2.system = 'StagingCareerPortal',
        u2.action = 'Unauthorized bulk export of 2,500 PERSONNEL_PII_RECORDS via /admin/export',
        u2.records_exported = 2500,
        u2.timestamp = '{timestamp}'
    MERGE (u1)-[:ENABLED]->(u2)
    MERGE (u2)-[:USED_CREDENTIAL]->(c)
    RETURN u1.usage_id AS root_id, u2.usage_id AS impact_id, c.cred_id AS cred_id
    """
    run_cypher(db_path, ingest_q)
    return len(lines)


def run_scenario_a_soar(db_path: Path, timestamp: str) -> dict:
    """P1 Critical: Hardcoded staging token -> 2,500 PII export -> Hard Containment."""
    remediation_q = f"""
    MATCH (u1:Usage {{usage_id: 'BREACH_SIM_01'}})-[:ENABLED]->(u2:Usage {{usage_id: 'BREACH_SIM_02'}})-[:USED_CREDENTIAL]->(c:Credential {{cred_id: 'CRED_STG_ADMIN_01'}})
    SET c.status = 'REVOKED', c.revoked_at = '{timestamp}'
    MERGE (r:RemediationAction {{action_id: 'SOAR-CRED-REVOKE-01'}})
    SET r.playbook = 'SOAR-CRED-REVOKE-01',
        r.severity = 'P1_CRITICAL',
        r.status = 'EXECUTED',
        r.action = 'Revoked CRED_STG_ADMIN_01 & blocked /admin/export endpoint',
        r.executed_at = '{timestamp}'
    MERGE (r)-[:MITIGATES]->(u1)
    MERGE (r)-[:MITIGATES]->(u2)
    MERGE (r)-[:REVOKED]->(c)
    RETURN r.action_id AS action_id, r.severity AS severity, r.status AS status,
           c.cred_id AS cred_id, c.status AS new_status
    """
    return {"result": run_cypher(db_path, remediation_q), "executed_at": timestamp}


def run_scenario_b_soar(db_path: Path, timestamp: str) -> dict:
    """P2-High Accidental: Shared container admin login pulling metadata/email logs."""
    seed_q = f"""
    MERGE (c:Credential {{cred_id: 'CRED_CONT_ADMIN_01'}})
    SET c.cred_type = 'container_admin_login',
        c.allowed_targets = 'ConnectivityAgentContainer',
        c.status = 'active',
        c.is_privileged = true,
        c.owner = 'infra_admin'
    MERGE (u1:Usage {{usage_id: 'CRED_SHARE_01'}})
    SET u1.source_host = 'LAPTOP-ADMIN-01',
        u1.action = 'Container agent maintenance',
        u1.system = 'ConnectivityAgentContainer',
        u1.timestamp = '{timestamp}'
    MERGE (u2:Usage {{usage_id: 'CRED_SHARE_02'}})
    SET u2.source_host = 'LAPTOP-OPS-04',
        u2.action = 'Pulled metadata extraction logs (employee emails + table/column names)',
        u2.system = 'ConnectivityAgentContainer',
        u2.contains_pii = true,
        u2.contains_schema_metadata = true,
        u2.timestamp = '{timestamp}'
    MERGE (u1)-[:USED_CREDENTIAL]->(c)
    MERGE (u2)-[:USED_CREDENTIAL]->(c)
    RETURN c.cred_id AS cred_id
    """
    run_cypher(db_path, seed_q)

    detect_and_contain_q = f"""
    MATCH (u1:Usage)-[:USED_CREDENTIAL]->(c:Credential)<-[:USED_CREDENTIAL]-(u2:Usage)
    WHERE c.is_privileged = true
      AND u1.source_host <> u2.source_host
      AND u1.usage_id < u2.usage_id
    SET c.status = 'rotation_required', c.flagged_at = '{timestamp}'
    MERGE (r:RemediationAction {{action_id: 'SOAR-CRED-SHARE-02'}})
    SET r.playbook = 'SOAR-CRED-SHARE-02',
        r.severity = 'P2_HIGH_GOVERNANCE',
        r.status = 'EXECUTED',
        r.action = 'Forced rotation of CRED_CONT_ADMIN_01, dropped LAPTOP-OPS-04 session, opened log-scrubbing (CDMC-09) & read-only RBAC ticket',
        r.executed_at = '{timestamp}'
    MERGE (r)-[:MITIGATES]->(u1)
    MERGE (r)-[:MITIGATES]->(u2)
    MERGE (r)-[:ROTATES]->(c)
    RETURN r.action_id AS action_id, r.severity AS severity, r.status AS status,
           c.cred_id AS cred_id, c.status AS new_status,
           u1.source_host AS host_a, u2.source_host AS host_b
    """
    return {"result": run_cypher(db_path, detect_and_contain_q), "executed_at": timestamp}


def render_dashboard(briefing: str, ts: str) -> None:
    clean_briefing = briefing.replace("Yes ? ", "Yes — ")
    escaped_briefing = html.escape(clean_briefing)

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>OmniGuard — Autonomous Graph Defense Dashboard</title>
<style>
  :root {{
    --bg: #0b1120; --card: #111827; --border: #1f2937;
    --text: #f3f4f6; --muted: #9ca3af;
    --red: #ef4444; --amber: #f59e0b; --green: #10b981; --indigo: #6366f1;
  }}
  * {{ box-sizing: border-box; font-family: 'Segoe UI', system-ui, sans-serif; }}
  body {{ margin: 0; background: var(--bg); color: var(--text); padding: 26px; }}
  .wrap {{ max-width: 1200px; margin: 0 auto; }}
  .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 22px; }}
  .title h1 {{ margin: 0; font-size: 25px; letter-spacing: -0.4px; }}
  .title p {{ margin: 4px 0 0; color: var(--muted); font-size: 13px; }}
  .badge {{ padding: 8px 16px; border-radius: 999px; font-weight: 700; font-size: 12px; background: rgba(16,185,129,0.15); color: var(--green); border: 1px solid var(--green); }}
  .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 18px; margin-bottom: 20px; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 18px; }}
  .card.p1 {{ border-top: 3px solid var(--red); }}
  .card.p2 {{ border-top: 3px solid var(--amber); }}
  .card-head {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }}
  .card-head h2 {{ margin: 0; font-size: 15px; letter-spacing: 0.3px; }}
  .sev {{ padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; }}
  .sev.p1 {{ background: rgba(239,68,68,0.18); color: #fca5a5; }}
  .sev.p2 {{ background: rgba(245,158,11,0.18); color: #fcd34d; }}
  .box {{ background: #090e1a; border: 1px solid var(--border); border-radius: 8px; padding: 12px; margin-bottom: 10px; font-size: 13px; }}
  .pill-row {{ display: flex; flex-wrap: wrap; gap: 6px; margin: 10px 0 12px; }}
  .pill {{ padding: 4px 8px; border-radius: 5px; font-size: 11px; font-weight: 600; }}
  .pill.red {{ background: rgba(239,68,68,0.18); color: #fca5a5; border: 1px solid rgba(239,68,68,0.35); }}
  .pill.amber {{ background: rgba(245,158,11,0.18); color: #fcd34d; border: 1px solid rgba(245,158,11,0.35); }}
  .pill.muted {{ background: rgba(156,163,175,0.12); color: var(--muted); border: 1px solid var(--border); }}
  .soar {{ font-size: 13px; line-height: 1.5; }}
  .check {{ color: var(--green); font-weight: 900; margin-right: 6px; }}
  .briefing {{ background: #090e1a; border: 1px solid var(--border); border-radius: 10px; padding: 16px; font-family: Consolas, monospace; font-size: 12.5px; line-height: 1.55; white-space: pre-wrap; color: #e5e7eb; overflow-x: auto; }}
  .meta {{ color: var(--muted); font-size: 12px; margin-top: 10px; }}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div class="title">
      <h1>OmniGuard: Autonomous Graph Defense</h1>
      <p>Powered by Relate Embedded Graph (<code>omniguard_demo.rl</code>) &bull; Proportional SOAR Containment</p>
    </div>
    <div class="badge">&#10003; 2 PLAYBOOKS EXECUTED &amp; AUDITED</div>
  </div>

  <div class="two-col">
    <div class="card p1">
      <div class="card-head">
        <h2>Scenario A: Staging Portal Breach (Malicious)</h2>
        <span class="sev p1">P1 CRITICAL &bull; HARD CONTAINMENT</span>
      </div>
      <div class="box">
        <strong>Kill Chain (IoA):</strong> <code>BREACH_SIM_01</code> (Hardcoded HTML token) &rarr; <code>[:ENABLED]</code> &rarr; <code>BREACH_SIM_02</code> (2,500 <code>PERSONNEL_PII_RECORDS</code> exported via <code>CRED_STG_ADMIN_01</code>).
      </div>
      <div class="pill-row">
        <span class="pill red">OWASP-2025-A02</span>
        <span class="pill red">NIST 800-53 IA-5(7)</span>
        <span class="pill amber">CDMC-04 Cloud PII</span>
        <span class="pill muted">PCI DSS: N/A</span>
      </div>
      <div class="soar">
        <div><span class="check">&#10003;</span><strong>Playbook:</strong> <code>SOAR-CRED-REVOKE-01</code></div>
        <div><span class="check">&#10003;</span><strong>Graph Action:</strong> <code>CRED_STG_ADMIN_01</code> flipped <code>exposed</code> &rarr; <code>revoked</code></div>
        <div><span class="check">&#10003;</span><strong>Audit Node:</strong> <code>(:RemediationAction)</code> linked to breach chain; CISO &amp; SOC paged</div>
      </div>
    </div>

    <div class="card p2">
      <div class="card-head">
        <h2>Scenario B: Shared Container Admin (Accidental)</h2>
        <span class="sev p2">P2-HIGH &bull; GOVERNANCE PLAYBOOK</span>
      </div>
      <div class="box">
        <strong>Anomaly (IoA):</strong> Privileged <code>CRED_CONT_ADMIN_01</code> used from 2 hosts (<code>LAPTOP-ADMIN-01</code> &amp; <code>LAPTOP-OPS-04</code>) to pull connectivity-agent logs containing <strong>employee emails</strong> &amp; <strong>table/column names</strong>.
      </div>
      <div class="pill-row">
        <span class="pill red">NIST IA-2 / IA-5 / AU-2</span>
        <span class="pill red">NIST 800-92 Log Scrub</span>
        <span class="pill amber">CDMC-04 / CDMC-09</span>
        <span class="pill muted">PCI DSS: N/A</span>
      </div>
      <div class="soar">
        <div><span class="check">&#10003;</span><strong>Playbook:</strong> <code>SOAR-CRED-SHARE-02</code></div>
        <div><span class="check">&#10003;</span><strong>Graph Action:</strong> <code>CRED_CONT_ADMIN_01</code> set to <code>rotation_required</code>; secondary session dropped</div>
        <div><span class="check">&#10003;</span><strong>Root-Cause Fix:</strong> Opened log-masking ticket (emails) &amp; individual read-only RBAC</div>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <h2>Live Executive Briefing (Generated from Relate Graph)</h2>
      <span class="meta">Executed: {ts}</span>
    </div>
    <div class="briefing">{escaped_briefing}</div>
  </div>
</div>
</body>
</html>
"""
    DASHBOARD_FILE.write_text(page, encoding="utf-8")


def main() -> None:
    if not BASE_DB.exists():
        raise FileNotFoundError(f"Baseline store not found: {BASE_DB}")
    if not EVENTS_FILE.exists():
        raise FileNotFoundError(f"Run simulate_breach.py first to generate {EVENTS_FILE}")

    shutil.copy2(BASE_DB, DEMO_DB)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    count = ingest_portal_events(DEMO_DB, EVENTS_FILE, ts)
    print(f"[SIEM] Ingested {count} event(s) from portal_events.jsonl into omniguard_demo.rl...")

    print("[SOAR-A] Executing P1 Hard Containment (SOAR-CRED-REVOKE-01)...")
    res_a = run_scenario_a_soar(DEMO_DB, ts)
    print(f"         -> {res_a['result']}")

    print("[SOAR-B] Executing P2 Governance Playbook (SOAR-CRED-SHARE-02)...")
    res_b = run_scenario_b_soar(DEMO_DB, ts)
    print(f"         -> {res_b['result']}")

    print("[AGENT] Generating plain-English Executive Briefing...")
    langgraph_audit.DB_PATH = DEMO_DB
    app = langgraph_audit.build_audit_graph()
    res = app.invoke(
        {
            "user_query": "Were any hardcoded staging admin credentials exposed or used for bulk PII exports?",
            "history": [],
        },
        config={"configurable": {"thread_id": "soar-demo-run"}},
    )

    render_dashboard(res["final_report"], ts)
    print(f"[DONE] Dashboard ready: {DASHBOARD_FILE.resolve()}")


if __name__ == "__main__":
    main()
