#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import urllib.request

URL = "https://api.codacy.com/api/api-docs/swagger.yaml"
MAX_BYTES = 8_000_000
TERMS = re.compile(r"token|account|invite|join|member|role|hook|integration|ssh|export|report", re.I)

req = urllib.request.Request(
    URL,
    headers={"Accept": "application/yaml,text/yaml,*/*", "User-Agent": "Codacy-H1-safe-validation/1.1"},
)
with urllib.request.urlopen(req, timeout=30) as response:
    status = int(response.status)
    content_type = response.headers.get("Content-Type", "")
    raw = response.read(MAX_BYTES + 1)
if len(raw) > MAX_BYTES:
    raise SystemExit("OpenAPI document exceeded safety limit")
text = raw.decode("utf-8", "replace")
lines = text.splitlines()

operations = []
current_path = None
current_method = None
current = None
for line in lines:
    path_match = re.match(r'^  ([^ ].*):\s*$', line)
    if path_match and path_match.group(1).startswith('/'):
        if current:
            operations.append(current)
        current = None
        current_path = path_match.group(1)
        current_method = None
        continue

    method_match = re.match(r'^    (get|post|put|patch|delete):\s*$', line)
    if method_match and current_path:
        if current:
            operations.append(current)
        current_method = method_match.group(1).upper()
        current = {
            "path": current_path,
            "method": current_method,
            "operation_id": None,
            "security_declared": False,
            "security_empty": False,
            "permission_extensions": [],
        }
        continue

    if current:
        op_match = re.match(r'^      operationId:\s*["\']?([^"\']+?)["\']?\s*$', line)
        if op_match:
            current["operation_id"] = op_match.group(1)
        if re.match(r'^      security:\s*$', line):
            current["security_declared"] = True
        if re.match(r'^      security:\s*\[\s*\]\s*$', line):
            current["security_declared"] = True
            current["security_empty"] = True
        ext_match = re.match(r'^      (x-[^:]*permission[^:]*):\s*(.*)$', line, re.I)
        if ext_match:
            current["permission_extensions"].append(ext_match.group(1))

if current:
    operations.append(current)

selected = [
    op for op in operations
    if TERMS.search(op["path"]) or TERMS.search(op.get("operation_id") or "")
]
print("CODACY_OPENAPI_PROBE=" + json.dumps({
    "status": status,
    "content_type": content_type,
    "bytes": len(raw),
    "sha256": hashlib.sha256(raw).hexdigest(),
    "global_security_declared": bool(re.search(r'^security:\s*$', text, re.M)),
    "selected_operations": selected,
}, sort_keys=True, separators=(",", ":")))
