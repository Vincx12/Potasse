#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import urllib.request

URL = "https://api.codacy.com/api/api-docs/swagger.yaml"
MAX_BYTES = 8_000_000

req = urllib.request.Request(
    URL,
    headers={"Accept": "application/yaml,text/yaml,*/*", "User-Agent": "Codacy-H1-safe-validation/1.4"},
)
with urllib.request.urlopen(req, timeout=30) as response:
    status = int(response.status)
    content_type = response.headers.get("Content-Type", "")
    raw = response.read(MAX_BYTES + 1)
if len(raw) > MAX_BYTES:
    raise SystemExit("OpenAPI document exceeded safety limit")
text = raw.decode("utf-8", "replace")

operations = []
current_path = None
current = None
for line in text.splitlines():
    path_match = re.match(r'^  ([^ ].*):\s*$', line)
    if path_match and path_match.group(1).startswith('/'):
        if current:
            operations.append(current)
        current = None
        current_path = path_match.group(1)
        continue
    method_match = re.match(r'^    (get|post|put|patch|delete):\s*$', line)
    if method_match and current_path:
        if current:
            operations.append(current)
        current = {
            "path": current_path,
            "method": method_match.group(1).upper(),
            "operation_id": None,
            "security_empty": False,
        }
        continue
    if current:
        op_match = re.match(r'^      operationId:\s*["\']?([^"\']+?)["\']?\s*$', line)
        if op_match:
            current["operation_id"] = op_match.group(1)
        if re.match(r'^      security:\s*\[\s*\]\s*$', line):
            current["security_empty"] = True
if current:
    operations.append(current)

public_ops = [
    {"method": op["method"], "path": op["path"], "operation_id": op["operation_id"]}
    for op in operations if op["security_empty"]
]
print("CODACY_PUBLIC_OPERATIONS=" + json.dumps({
    "status": status,
    "content_type": content_type,
    "bytes": len(raw),
    "sha256": hashlib.sha256(raw).hexdigest(),
    "count": len(public_ops),
    "operations": public_ops,
}, sort_keys=True, separators=(",", ":")))
