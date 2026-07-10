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

BASE = "https://api.codacy.com/api/v3"
ALLOWED_HOSTS = {"api.codacy.com", "app.codacy.com"}
PATHS = [
    "/admin/license",
    "/admin/dormantAccounts",
    "/admin/security/penTest/reports",
]
MAX_BODY = 65536


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
            raise RuntimeError("blocked out-of-scope redirect")
        return None


opener = urllib.request.build_opener(NoRedirect())


def summarize(value, key=""):
    if re.search(r"token|secret|credential|password|api.?key|cookie|authorization|email|license", key, re.I):
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
        return {"type": "string", "length": len(value)}
    return value


def get(path, invalid=False):
    url = BASE + path
    headers = {"Accept": "application/json", "User-Agent": "Codacy-H1-safe-validation/2.1"}
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
        target = urllib.parse.urlparse(urllib.parse.urljoin(url, location))
        if target.scheme != "https" or target.hostname not in ALLOWED_HOSTS:
            raise RuntimeError("out-of-scope Location")
    body = {"non_json": True}
    if "json" in content_type.lower():
        try:
            body = json.loads(raw.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            body = {"invalid_json": True}
    time.sleep(1)
    return {
        "path": path,
        "credential": "invalid" if invalid else "none",
        "status": status,
        "content_type": content_type,
        "body_length": len(raw),
        "body_sha256": hashlib.sha256(raw).hexdigest(),
        "redirect_present": bool(location),
        "body_summary": summarize(body),
    }


results = []
for path in PATHS:
    no_session = get(path)
    results.append(no_session)
    if 200 <= no_session["status"] < 300:
        break
    invalid = get(path, invalid=True)
    results.append(invalid)
    if 200 <= invalid["status"] < 300:
        break

print("CODACY_ADMIN_PROBE=" + json.dumps(results, sort_keys=True, separators=(",", ":")))
