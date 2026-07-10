#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
import urllib.request

URL = "https://app.codacy.com/static/assets/index-C5YO_nN1.js.map"
ALLOWED_HOSTS = {"app.codacy.com", "api.codacy.com"}
MAX_BYTES = 40_000_000


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
            raise RuntimeError("blocked out-of-scope redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


opener = urllib.request.build_opener(SafeRedirect())
req = urllib.request.Request(
    URL,
    headers={"Accept": "application/json", "User-Agent": "Codacy-H1-safe-validation/1.7"},
)
with opener.open(req, timeout=45) as response:
    status = int(response.status)
    content_type = response.headers.get("Content-Type", "")
    raw = response.read(MAX_BYTES + 1)
if len(raw) > MAX_BYTES:
    raise SystemExit("source map exceeded 40 MB safety limit")
source_map = json.loads(raw.decode("utf-8", "replace"))
sources = source_map.get("sources") or []
contents = source_map.get("sourcesContent") or []

secret_patterns = {
    "pem_private_key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "aws_access_key": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    "github_token": r"\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{40,255})\b",
    "gitlab_token": r"\bglpat-[A-Za-z0-9_-]{20,255}\b",
    "slack_token": r"\bxox[baprs]-[A-Za-z0-9-]{20,255}\b",
    "stripe_live_secret": r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,255}\b",
}
secret_fingerprints = []
source_hits = []
path_terms = re.compile(r"auth|permission|role|token|integration|organization|repository|billing|invite", re.I)
keywords = {
    "repository_token_operations": re.compile(r"listRepositoryApiTokens|createRepositoryApiToken|deleteRepositoryApiToken"),
    "account_token_operations": re.compile(r"getUserApiTokens|createUserApiToken|deleteUserApiToken"),
    "permission_logic": re.compile(r"hasPermission|permissions|RepositoryAdmin|repository admin", re.I),
    "api_token_headers": re.compile(r"api-token|project-token", re.I),
    "oauth_state": re.compile(r"oauth.{0,60}state|state.{0,60}oauth", re.I | re.S),
}

for index, source in enumerate(sources):
    content = contents[index] if index < len(contents) and isinstance(contents[index], str) else ""
    categories = sorted(name for name, pattern in keywords.items() if pattern.search(content))
    if categories or path_terms.search(str(source)):
        source_hits.append({"source": str(source)[-240:], "categories": categories})
    for kind, pattern in secret_patterns.items():
        for match in re.finditer(pattern, content):
            value = match.group(0)
            secret_fingerprints.append({
                "kind": kind,
                "source": str(source)[-160:],
                "length": len(value),
                "sha256": hashlib.sha256(value.encode()).hexdigest(),
            })

unique_secrets = []
seen_secret = set()
for finding in secret_fingerprints:
    key = (finding["kind"], finding["sha256"])
    if key not in seen_secret:
        seen_secret.add(key)
        unique_secrets.append(finding)

print("CODACY_SOURCEMAP_AUDIT=" + json.dumps({
    "status": status,
    "content_type": content_type,
    "bytes": len(raw),
    "sha256": hashlib.sha256(raw).hexdigest(),
    "source_count": len(sources),
    "sources_content_count": sum(isinstance(v, str) for v in contents),
    "secret_fingerprints": unique_secrets[:50],
    "authorization_sources": source_hits[:250],
}, sort_keys=True, separators=(",", ":")))
