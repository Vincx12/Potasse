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
ALLOWED_HOSTS = {"app.codacy.com", "api.codacy.com"}
MAX_HTML = 1_000_000
MAX_ASSET = 12_000_000


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
            raise RuntimeError("blocked out-of-scope redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Collector(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "script" and values.get("src"):
            self.scripts.append(values["src"])


opener = urllib.request.build_opener(SafeRedirect())


def fetch(url, accept, limit):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise RuntimeError("blocked out-of-scope URL")
    req = urllib.request.Request(
        url,
        headers={"Accept": accept, "User-Agent": "Codacy-H1-safe-validation/1.6"},
    )
    with opener.open(req, timeout=30) as response:
        raw = response.read(limit + 1)
        status = int(response.status)
        content_type = response.headers.get("Content-Type", "")
    if len(raw) > limit:
        raise RuntimeError("asset exceeded safety limit")
    return status, content_type, raw


def match_fingerprints(text):
    patterns = {
        "pem_private_key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "aws_access_key": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        "github_classic_token": r"\bgh[pousr]_[A-Za-z0-9]{30,255}\b",
        "github_fine_grained_token": r"\bgithub_pat_[A-Za-z0-9_]{40,255}\b",
        "gitlab_token": r"\bglpat-[A-Za-z0-9_-]{20,255}\b",
        "slack_token": r"\bxox[baprs]-[A-Za-z0-9-]{20,255}\b",
        "stripe_live_secret": r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,255}\b",
        "google_api_key": r"\bAIza[0-9A-Za-z_-]{35}\b",
        "basic_auth_url": r"https://[^\s/:@]{2,80}:[^\s/@]{6,160}@[^\s/]+",
    }
    findings = []
    for kind, pattern in patterns.items():
        for match in re.finditer(pattern, text):
            value = match.group(0)
            findings.append({
                "kind": kind,
                "length": len(value),
                "sha256": hashlib.sha256(value.encode()).hexdigest(),
            })
    assignment = re.compile(
        r"(?i)(client[_-]?secret|api[_-]?token|access[_-]?token|webhook[_-]?secret)"
        r"[\s\"']{0,8}[:=][\s\"']{0,8}([A-Za-z0-9._~+/=-]{16,255})"
    )
    for match in assignment.finditer(text):
        value = match.group(2)
        findings.append({
            "kind": "secret_assignment:" + match.group(1).lower(),
            "length": len(value),
            "sha256": hashlib.sha256(value.encode()).hexdigest(),
        })
    unique = []
    seen = set()
    for finding in findings:
        key = (finding["kind"], finding["sha256"])
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique[:50]


def extract_env_keys(text):
    keys = set()
    for pattern in [
        r"\b([A-Z][A-Z0-9_]{2,80})\s*:",
        r"\b(?:window\.)?([A-Z][A-Z0-9_]{2,80})\s*=",
        r"[\"']([A-Z][A-Z0-9_]{2,80})[\"']\s*:",
    ]:
        keys.update(re.findall(pattern, text))
    return sorted(keys)[:200]


def extract_sensitive_routes(text):
    route_re = re.compile(r"[\"'](\/[^\"'\s]{2,220})[\"']")
    terms = re.compile(r"token|integration|oauth|callback|join|invite|member|role|admin|report|export|ssh|billing|settings", re.I)
    routes = set()
    for route in route_re.findall(text):
        if terms.search(route) and not route.startswith("//"):
            routes.add(route)
    return sorted(routes)[:200]


root_status, root_type, root_raw = fetch(ROOT, "text/html", MAX_HTML)
collector = Collector()
collector.feed(root_raw.decode("utf-8", "replace"))
results = []
for source in collector.scripts:
    url = urllib.parse.urljoin(ROOT, source)
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        continue
    status, content_type, raw = fetch(url, "application/javascript,text/javascript,*/*", MAX_ASSET)
    text = raw.decode("utf-8", "replace")
    source_maps = re.findall(r"sourceMappingURL=([^\s*]+)", text[-2000:])
    results.append({
        "path": parsed.path,
        "query_present": bool(parsed.query),
        "status": status,
        "content_type": content_type,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "env_keys": extract_env_keys(text) if parsed.path.endswith("/env.js") else [],
        "sensitive_routes": extract_sensitive_routes(text),
        "secret_fingerprints": match_fingerprints(text),
        "source_maps": source_maps[:10],
    })

print("CODACY_FRONTEND_STATIC_AUDIT=" + json.dumps({
    "root_status": root_status,
    "root_content_type": root_type,
    "root_bytes": len(root_raw),
    "root_sha256": hashlib.sha256(root_raw).hexdigest(),
    "scripts": results,
}, sort_keys=True, separators=(",", ":")))
