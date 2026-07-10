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
OWNER = "Vincx12"
REPOSITORIES = ["Potasse", "Flappy-beer-", "Vincx", "Vincxcall"]
ALLOWED_HOSTS = {"api.codacy.com", "app.codacy.com"}
MAX_BODY = 65536


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
            raise RuntimeError("blocked out-of-scope redirect")
        return None


opener = urllib.request.build_opener(NoRedirect())


def summarize_json(value):
    def walk(v):
        if isinstance(v, dict):
            keys = sorted(str(k) for k in v.keys())
            token_keys = sorted(k for k in keys if re.search(r"token|secret|credential|password|api.?key", k, re.I))
            return {
                "type": "object",
                "keys": keys[:30],
                "token_like_keys": token_keys,
                "data": walk(v.get("data")) if "data" in v else None,
                "error": str(v.get("error"))[:200] if "error" in v else None,
            }
        if isinstance(v, list):
            return {"type": "array", "count": len(v), "first": walk(v[0]) if v else None}
        if isinstance(v, str):
            return {"type": "string", "length": len(v)}
        if v is None:
            return {"type": "null"}
        return {"type": type(v).__name__}
    return walk(value)


def request(name, url, headers=None):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise RuntimeError("blocked out-of-scope URL")
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"Accept": "application/json", "User-Agent": "Codacy-H1-safe-validation/1.3", **(headers or {})},
    )
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
        raise RuntimeError("response exceeded 64 KiB safety limit")
    if location:
        target = urllib.parse.urlparse(urllib.parse.urljoin(url, location))
        if target.scheme != "https" or target.hostname not in ALLOWED_HOSTS:
            raise RuntimeError("blocked out-of-scope Location header")
    summary = {"type": "non_json"}
    if "json" in content_type.lower():
        try:
            summary = summarize_json(json.loads(raw.decode("utf-8", "replace")))
        except json.JSONDecodeError:
            summary = {"type": "invalid_json"}
    result = {
        "name": name,
        "method": "GET",
        "url": url,
        "status": status,
        "content_type": content_type,
        "body_length": len(raw),
        "body_sha256": hashlib.sha256(raw).hexdigest(),
        "redirect_present": bool(location),
        "body_summary": summary,
    }
    time.sleep(1)
    return result


results = []
invalid = "invalid_" + secrets.token_urlsafe(24)
found = False
for canonical_repo in REPOSITORIES:
    candidates = []
    for owner, repo in [
        (OWNER, canonical_repo),
        (OWNER.lower(), canonical_repo),
        (OWNER.lower(), canonical_repo.lower()),
    ]:
        if (owner, repo) not in candidates:
            candidates.append((owner, repo))

    for owner_name, repo_name in candidates:
        owner = urllib.parse.quote(owner_name, safe="")
        repository = urllib.parse.quote(repo_name, safe="")
        analysis_url = f"{BASE}/analysis/organizations/gh/{owner}/repositories/{repository}"
        existence = request(f"{owner_name}/{repo_name}:public_analysis_control", analysis_url)
        results.append(existence)
        if 200 <= existence["status"] < 300 and existence["body_summary"].get("type") == "object":
            tokens_url = f"{BASE}/organizations/gh/{owner}/repositories/{repository}/tokens"
            no_session = request(f"{owner_name}/{repo_name}:tokens_no_session", tokens_url)
            results.append(no_session)
            if not 200 <= no_session["status"] < 300:
                results.append(request(
                    f"{owner_name}/{repo_name}:tokens_invalid_session",
                    tokens_url,
                    {"api-token": invalid},
                ))
            found = True
            break
    if found:
        break

print("CODACY_CASE_PROBE=" + json.dumps(results, sort_keys=True, separators=(",", ":")))
