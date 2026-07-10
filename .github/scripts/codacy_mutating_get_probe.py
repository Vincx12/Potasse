#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

APP_BASE = "https://app.codacy.com/api/v3"
OPENAPI_URL = "https://api.codacy.com/api/api-docs/swagger.yaml"
ALLOWED_HOSTS = {"app.codacy.com", "api.codacy.com"}
OWNED_REPOSITORY = "/organizations/gh/Vincx12/repositories/Potasse"
TARGET_PATH = OWNED_REPOSITORY + "/integrations/postCommitHook"
ANALYSIS_PATH = "/analysis/organizations/gh/Vincx12/repositories/Potasse"
MAX_BODY = 65536
MAX_SCHEMA = 8_000_000


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
            raise RuntimeError("blocked out-of-scope redirect")
        return None


opener = urllib.request.build_opener(NoRedirect())


def summarize(value, key=""):
    if re.search(r"token|secret|credential|password|api.?key|cookie|authorization|email", key, re.I):
        if isinstance(value, str):
            return {"redacted": True, "type": "string", "length": len(value)}
        if isinstance(value, list):
            return {"redacted": True, "type": "array", "count": len(value)}
        return {"redacted": True, "type": type(value).__name__}
    if isinstance(value, dict):
        return {str(k): summarize(v, str(k)) for k, v in list(value.items())[:30]}
    if isinstance(value, list):
        return {"type": "array", "count": len(value), "first": summarize(value[0]) if value else None}
    if isinstance(value, str):
        return {"type": "string", "length": len(value), "sample": value[:100] if len(value) <= 100 else None}
    return value


def request(path, label, invalid=False):
    url = APP_BASE + path
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise RuntimeError("out-of-scope request")
    headers = {"Accept": "application/json", "User-Agent": "Codacy-H1-safe-validation/2.2"}
    if invalid:
        headers["api-token"] = "invalid_" + secrets.token_urlsafe(24)
    req = urllib.request.Request(url, method="GET", headers=headers)
    try:
        with opener.open(req, timeout=20) as response:
            status = int(response.status)
            content_type = response.headers.get("Content-Type", "")
            location = response.headers.get("Location", "")
            raw = response.read(MAX_BODY + 1)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        content_type = exc.headers.get("Content-Type", "") if exc.headers else ""
        location = exc.headers.get("Location", "") if exc.headers else ""
        raw = exc.read(MAX_BODY + 1)
    if len(raw) > MAX_BODY:
        raise RuntimeError("response exceeded safety limit")
    if location:
        redirect = urllib.parse.urlparse(urllib.parse.urljoin(url, location))
        if redirect.scheme != "https" or redirect.hostname not in ALLOWED_HOSTS:
            raise RuntimeError("out-of-scope Location")
    body = {"non_json": True}
    if "json" in content_type.lower():
        try:
            body = json.loads(raw.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            body = {"invalid_json": True}
    time.sleep(1)
    return {
        "label": label,
        "method": "GET",
        "path": path,
        "credential": "invalid" if invalid else "none",
        "status": status,
        "content_type": content_type,
        "body_length": len(raw),
        "body_sha256": hashlib.sha256(raw).hexdigest(),
        "redirect_present": bool(location),
        "body_summary": summarize(body),
    }


def openapi_operations():
    req = urllib.request.Request(
        OPENAPI_URL,
        headers={"Accept": "application/yaml,text/yaml,*/*", "User-Agent": "Codacy-H1-safe-validation/2.2"},
    )
    with opener.open(req, timeout=30) as response:
        raw = response.read(MAX_SCHEMA + 1)
        status = int(response.status)
    if len(raw) > MAX_SCHEMA:
        raise RuntimeError("OpenAPI document exceeded safety limit")
    text = raw.decode("utf-8", "replace")
    operations = []
    current_path = None
    current = None
    for line in text.splitlines():
        path_match = re.match(r"^  (/[^:]+):\s*$", line)
        if path_match:
            if current:
                operations.append(current)
            current = None
            current_path = path_match.group(1)
            continue
        method_match = re.match(r"^    (get|post|put|patch|delete):\s*$", line)
        if method_match and current_path:
            if current:
                operations.append(current)
            current = {
                "path": current_path,
                "method": method_match.group(1).upper(),
                "operation_id": None,
                "security_empty": False,
                "security_declared": False,
            }
            continue
        if current:
            operation_match = re.match(r"^      operationId:\s*[\"']?([^\"']+?)[\"']?\s*$", line)
            if operation_match:
                current["operation_id"] = operation_match.group(1)
            if re.match(r"^      security:\s*", line):
                current["security_declared"] = True
            if re.match(r"^      security:\s*\[\s*\]\s*$", line):
                current["security_empty"] = True
    if current:
        operations.append(current)
    suspicious = []
    mutation_verb = re.compile(r"^(create|delete|update|set|add|remove|regenerate|reset|sync|follow|unfollow|bypass|promote|apply|reanalyze|trigger|start|enable|disable)", re.I)
    for operation in operations:
        if operation["method"] == "GET" and mutation_verb.search(operation.get("operation_id") or ""):
            suspicious.append(operation)
    exact = [operation for operation in operations if operation["path"].endswith("/integrations/postCommitHook")]
    return {
        "status": status,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "suspicious_get_operations": suspicious,
        "post_commit_hook_operations": exact,
    }


schema = openapi_operations()
results = [request("/version", "public_control"), request(ANALYSIS_PATH, "analysis_before")]
probe = request(TARGET_PATH, "post_commit_hook_no_session")
results.append(probe)
if not (200 <= probe["status"] < 300):
    probe = request(TARGET_PATH, "post_commit_hook_invalid_token", invalid=True)
    results.append(probe)
if 200 <= probe["status"] < 300:
    results.append(request(ANALYSIS_PATH, "analysis_after"))

print("CODACY_MUTATING_GET_PROBE=" + json.dumps({"openapi": schema, "requests": results}, sort_keys=True, separators=(",", ":")))
