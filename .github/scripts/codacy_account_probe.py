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
MAX_BODY = 65536
PUBLIC_CONTROL = "/login/integrations"
SENSITIVE_PATHS = [
    "/user/tokens",
    "/user/integrations",
    "/user/enterprise/integrations",
    "/user/organizations/gh",
]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
            raise RuntimeError("blocked out-of-scope redirect")
        return None


opener = urllib.request.build_opener(NoRedirect())


def summarize(value):
    def walk(v, key=""):
        if re.search(r"token|secret|credential|password|api.?key|cookie|authorization|email", key, re.I):
            if isinstance(v, str):
                return {"redacted": True, "type": "string", "length": len(v)}
            if isinstance(v, list):
                return {"redacted": True, "type": "array", "count": len(v)}
            return {"redacted": True, "type": type(v).__name__}
        if isinstance(v, dict):
            return {str(k): walk(val, str(k)) for k, val in list(v.items())[:30]}
        if isinstance(v, list):
            return {"type": "array", "count": len(v), "first": walk(v[0]) if v else None}
        if isinstance(v, str):
            return {"type": "string", "length": len(v), "sample": v[:120] if len(v) <= 120 else None}
        if v is None:
            return None
        return v
    return walk(value)


def get(path, label, invalid=False):
    url = BASE + path
    parsed = urllib.parse.urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS or parsed.scheme != "https":
        raise RuntimeError("out-of-scope URL")
    headers = {
        "Accept": "application/json",
        "User-Agent": "Codacy-H1-safe-validation/1.2",
    }
    if invalid:
        headers["api-token"] = "invalid_" + secrets.token_urlsafe(24)
    req = urllib.request.Request(url, method="GET", headers=headers)
    raw = b""
    location = ""
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
        raise RuntimeError("response exceeded 64 KiB")
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
    result = {
        "label": label,
        "path": path,
        "status": status,
        "content_type": content_type,
        "body_length": len(raw),
        "body_sha256": hashlib.sha256(raw).hexdigest(),
        "redirect_present": bool(location),
        "body_summary": summarize(body),
    }
    time.sleep(1)
    return result


results = [get(PUBLIC_CONTROL, "public_control")]
if not (200 <= results[0]["status"] < 300):
    raise SystemExit("public control failed")

for path in SENSITIVE_PATHS:
    no_session = get(path, path + ":no_session")
    results.append(no_session)
    if 200 <= no_session["status"] < 300:
        break
    invalid = get(path, path + ":invalid_token", invalid=True)
    results.append(invalid)
    if 200 <= invalid["status"] < 300:
        break

print("CODACY_ACCOUNT_PROBE=" + json.dumps(results, sort_keys=True, separators=(",", ":")))
