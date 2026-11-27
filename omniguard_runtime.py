import json
import os
import subprocess
from pathlib import Path
import relate

BASE_DIR = Path(os.environ.get('OMNIGUARD_DIR', Path(__file__).resolve().parent))
SIGNALS_PATH = Path(os.environ.get('OMNIGUARD_SIGNALS_FILE', BASE_DIR / 'secrets_signals.json'))

def resolve_db_path(override=None):
    if override:
        return Path(override)
    env_db = os.environ.get('OMNIGUARD_DB')
    if env_db:
        return Path(env_db)
    for candidate in (BASE_DIR / 'omniguard.rl', BASE_DIR / 'omniguard_demo.rl'):
        if candidate.exists():
            return candidate
    return BASE_DIR / 'omniguard_demo.rl'

def load_signals_config(config_path=None):
    target = Path(config_path) if config_path else SIGNALS_PATH
    if target.exists():
        return json.loads(target.read_text(encoding='utf-8'))
    return {'min_length': 16, 'min_entropy': 3.6, 'context_keywords': ['token', 'secret', 'key', 'bearer', 'password', 'auth', 'api_key'], 'ignore_values': ['null', 'none', 'true', 'false']}

def query_relate_rows(cypher, db_path=None):
    target = str(resolve_db_path(db_path))
    try:
        with relate.connect(target) as conn:
            with conn.cursor() as cur:
                cur.execute(cypher)
                return cur.fetchall()
    except Exception:
        res = subprocess.run(['relate', 'query', cypher, '--database', target, '--mode', 'table'], capture_output=True, text=True, check=False)
        return res.stdout.splitlines()

def is_credential_revoked(cred_id, db_path=None):
    target = resolve_db_path(db_path)
    if not target.exists() or not cred_id:
        return False
    safe_id = str(cred_id).replace('"', '').replace("'", '').strip()
    query = f'MATCH (c:Credential {{id: "{safe_id}"}}) RETURN c.status;'
    for row in query_relate_rows(query, target):
        text = ' '.join(str(x) for x in row) if isinstance(row, (list, tuple)) else str(row)
        if 'REVOKED' in text.upper():
            return True
    return False
