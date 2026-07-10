#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import html.parser
import json
import re
import urllib.error
import urllib.parse
import urllib.request

ROOT = "https://app.codacy.com/"
LOGIN = "https://app.codacy.com/login-with/gh"
ALLOWED_HOSTS = {"app.codacy.com", "api.codacy.com"}
MAX_HTML = 1_000_000
MAX_ASSET = 12_000_000


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https":
            raise RuntimeError("blocked non-HTTPS redirect")
        return None


class Scripts(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.values = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "script" and values.get("src"):
            self.values.append(values["src"])


opener = urllib.request.build_opener(NoRedirect())


def cookie_metadata(headers):
    cookies = headers.get_all("Set-Cookie") or []
    result = []
    for raw in cookies:
        parts = [part.strip() for part in raw.split(";")]
        name = parts[0].split("=", 1)[0] if parts else ""
        attrs = {}
        for part in parts[1:]:
            key, _, value = part.partition("=")
            attrs[key.lower()] = value or True
        result.append({
            "name": name,
            "secure": "secure" in attrs,
            "httponly": "httponly" in attrs,
            "samesite": str(attrs.get("samesite", "unspecified")),
            "path": str(attrs.get("path", "")),
            "domain_present": "domain" in attrs,
            "max_age_present": "max-age" in attrs,
        })
    return result


def get_no_follow(url, limit):
    req = urllib.request.Request(
        url,
        headers={"Accept": "text/html,application/json,*/*", "User-Agent": "Codacy-H1-safe-validation/2.3"},
    )
    try:
        with opener.open(req, timeout=25) as response:
            status = int(response.status)
            headers = response.headers
            raw = response.read(limit + 1)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        headers = exc.headers
        raw = exc.read(limit + 1)
    if len(raw) > limit:
        raise RuntimeError("response exceeded safety limit")
    location = headers.get("Location", "") if headers else ""
    parsed_location = urllib.parse.urlparse(urllib.parse.urljoin(url, location)) if location else None
    return {
        "status": status,
        "content_type": headers.get("Content-Type", "") if headers else "",
        "body_length": len(raw),
        "body_sha256": hashlib.sha256(raw).hexdigest(),
        "cookies": cookie_metadata(headers) if headers else [],
        "redirect": {
            "present": bool(location),
            "scheme": parsed_location.scheme if parsed_location else "",
            "host": parsed_location.hostname if parsed_location else "",
            "path": parsed_location.path if parsed_location else "",
            "query_keys": sorted(urllib.parse.parse_qs(parsed_location.query).keys()) if parsed_location else [],
        },
        "raw": raw,
    }


root = get_no_follow(ROOT, MAX_HTML)
parser = Scripts()
parser.feed(root.pop("raw").decode("utf-8", "replace"))
script_urls = [urllib.parse.urljoin(ROOT, src) for src in parser.values]
asset_url = next((url for url in script_urls if "/static/assets/" in urllib.parse.urlparse(url).path), None)
asset_audit = None
if asset_url:
    parsed = urllib.parse.urlparse(asset_url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise RuntimeError("blocked out-of-scope asset")
    asset = get_no_follow(asset_url, MAX_ASSET)
    text = asset.pop("raw").decode("utf-8", "replace")
    indicators = {
        "csrf": len(re.findall(r"csrf", text, re.I)),
        "xsrf": len(re.findall(r"xsrf", text, re.I)),
        "x_csrf_token": len(re.findall(r"x-csrf-token", text, re.I)),
        "x_xsrf_token": len(re.findall(r"x-xsrf-token", text, re.I)),
        "play_session": len(re.findall(r"PLAY_SESSION", text)),
        "credentials_include": len(re.findall(r"credentials\s*:\s*[\"']include[\"']", text)),
        "credentials_same_origin": len(re.findall(r"credentials\s*:\s*[\"']same-origin[\"']", text)),
        "with_credentials": len(re.findall(r"withCredentials", text)),
    }
    asset_audit = {
        "status": asset["status"],
        "path": parsed.path,
        "body_length": asset["body_length"],
        "body_sha256": asset["body_sha256"],
        "indicators": indicators,
    }

login = get_no_follow(LOGIN, 65536)
login.pop("raw")

print("CODACY_CSRF_POSTURE=" + json.dumps({"root": root, "login": login, "asset": asset_audit}, sort_keys=True, separators=(",", ":")))
