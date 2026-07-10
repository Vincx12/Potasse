#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import http.cookiejar
import json
import urllib.error
import urllib.parse
import urllib.request

CANDIDATES = [
    "https://api.codacy.com/api/v3/login-with/gh",
    "https://app.codacy.com/api/v3/login-with/gh",
]
ALLOWED_REQUEST_HOSTS = {"api.codacy.com", "app.codacy.com"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def digest(value: str) -> str | None:
    return hashlib.sha256(value.encode()).hexdigest() if value else None


def one_request(url: str) -> dict:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_REQUEST_HOSTS:
        raise RuntimeError("out-of-scope request")
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPCookieProcessor(jar))
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"Accept": "text/html,application/json", "User-Agent": "Codacy-H1-safe-validation/2.2"},
    )
    try:
        with opener.open(req, timeout=20) as response:
            status = int(response.status)
            location = response.headers.get("Location", "")
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        location = exc.headers.get("Location", "") if exc.headers else ""

    target = urllib.parse.urlparse(urllib.parse.urljoin(url, location)) if location else None
    query = urllib.parse.parse_qs(target.query, keep_blank_values=True) if target else {}
    state = query.get("state", [""])[0]
    nonce = query.get("nonce", [""])[0]
    challenge = query.get("code_challenge", [""])[0]
    redirect_uri = query.get("redirect_uri", [""])[0]
    cookie_meta = sorted({
        (cookie.name, bool(cookie.secure), cookie.has_nonstandard_attr("HttpOnly"), cookie.get_nonstandard_attr("SameSite"))
        for cookie in jar
    })
    return {
        "request_host": parsed.hostname,
        "status": status,
        "redirect_present": bool(location),
        "redirect_host": target.hostname if target else None,
        "redirect_path": target.path if target else None,
        "query_keys": sorted(query.keys()),
        "state_present": bool(state),
        "state_length": len(state),
        "state_sha256": digest(state),
        "nonce_present": bool(nonce),
        "nonce_length": len(nonce),
        "nonce_sha256": digest(nonce),
        "pkce_present": bool(challenge),
        "pkce_length": len(challenge),
        "pkce_method": query.get("code_challenge_method", [None])[0],
        "redirect_uri_host": urllib.parse.urlparse(redirect_uri).hostname if redirect_uri else None,
        "cookies": [
            {"name": name, "secure": secure, "http_only": http_only, "same_site": same_site}
            for name, secure, http_only, same_site in cookie_meta
        ],
    }


selected = None
for candidate in CANDIDATES:
    first = one_request(candidate)
    if first["redirect_present"]:
        second = one_request(candidate)
        selected = {"url": candidate, "first": first, "second": second}
        s1 = first.get("state_sha256")
        s2 = second.get("state_sha256")
        selected["state_unique_across_fresh_sessions"] = bool(s1 and s2 and s1 != s2)
        n1 = first.get("nonce_sha256")
        n2 = second.get("nonce_sha256")
        selected["nonce_unique_across_fresh_sessions"] = bool(n1 and n2 and n1 != n2)
        break

print("CODACY_OAUTH_PROBE=" + json.dumps(selected or {"error": "no redirect endpoint found"}, sort_keys=True, separators=(",", ":")))
