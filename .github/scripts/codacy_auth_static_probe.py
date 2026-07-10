#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import html.parser
import json
import re
import urllib.parse
import urllib.request

ROOT = "https://app.codacy.com/"
ALLOWED_HOSTS = {"app.codacy.com", "api.codacy.com"}
MAX_BYTES = 12_000_000
TARGET_ROUTE = "/organizations/{provider}/{remoteOrganizationName}/repositories/{repositoryName}/integrations/postCommitHook"


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
            raise RuntimeError("blocked out-of-scope redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Scripts(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.values = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "script" and values.get("src"):
            self.values.append(values["src"])


opener = urllib.request.build_opener(SafeRedirect())


def fetch(url, limit=MAX_BYTES):
    req = urllib.request.Request(
        url,
        headers={"Accept": "*/*", "User-Agent": "Codacy-H1-safe-validation/1.8"},
    )
    with opener.open(req, timeout=35) as response:
        raw = response.read(limit + 1)
        status = int(response.status)
        content_type = response.headers.get("Content-Type", "")
    if len(raw) > limit:
        raise RuntimeError("asset exceeded safety limit")
    return status, content_type, raw


root_status, _, root_raw = fetch(ROOT, 1_000_000)
parser = Scripts()
parser.feed(root_raw.decode("utf-8", "replace"))
script_urls = [urllib.parse.urljoin(ROOT, value) for value in parser.values]
env_url = next(url for url in script_urls if urllib.parse.urlparse(url).path.endswith("/env.js"))
bundle_url = next(url for url in script_urls if "/static/assets/" in urllib.parse.urlparse(url).path)

env_status, _, env_raw = fetch(env_url, 200_000)
bundle_status, _, bundle_raw = fetch(bundle_url)
env_text = env_raw.decode("utf-8", "replace")
bundle_text = bundle_raw.decode("utf-8", "replace")

env_keys = sorted(set(re.findall(r"(?:[,{]\s*|^)\"?([A-Za-z_$][A-Za-z0-9_$-]{1,80})\"?\s*:", env_text)))
url_hosts = sorted(set(
    urllib.parse.urlparse(value).hostname
    for value in re.findall(r"https://[^\s\"']+", env_text)
    if urllib.parse.urlparse(value).hostname
))

transport_counts = {
    "credentials_include": len(re.findall(r"credentials\s*:\s*[\"']include[\"']", bundle_text)),
    "credentials_same_origin": len(re.findall(r"credentials\s*:\s*[\"']same-origin[\"']", bundle_text)),
    "with_credentials": len(re.findall(r"withCredentials", bundle_text)),
    "api_token_header": len(re.findall(r"api-token", bundle_text, re.I)),
    "project_token_header": len(re.findall(r"project-token", bundle_text, re.I)),
    "authorization_header": len(re.findall(r"Authorization", bundle_text)),
}

route_positions = [m.start() for m in re.finditer(re.escape(TARGET_ROUTE), bundle_text)]
operation_positions = [m.start() for m in re.finditer(r"createPostCommitHook", bundle_text)]
windows = []
for position in (route_positions + operation_positions)[:10]:
    window = bundle_text[max(0, position - 800): position + 800]
    windows.append({
        "contains_get_literal": bool(re.search(r"[\"']GET[\"']|method\s*:\s*[\"']get[\"']", window, re.I)),
        "contains_post_literal": bool(re.search(r"[\"']POST[\"']|method\s*:\s*[\"']post[\"']", window, re.I)),
        "contains_credentials_include": bool(re.search(r"credentials\s*:\s*[\"']include[\"']", window)),
        "contains_with_credentials": "withCredentials" in window,
        "contains_api_token": bool(re.search(r"api-token", window, re.I)),
        "contains_query_client": bool(re.search(r"queryClient|useQuery|queryFn", window)),
        "contains_mutation_client": bool(re.search(r"useMutation|mutationFn", window)),
        "window_sha256": hashlib.sha256(window.encode()).hexdigest(),
    })

print("CODACY_AUTH_STATIC_AUDIT=" + json.dumps({
    "root_status": root_status,
    "env_status": env_status,
    "bundle_status": bundle_status,
    "env_path": urllib.parse.urlparse(env_url).path,
    "env_bytes": len(env_raw),
    "env_sha256": hashlib.sha256(env_raw).hexdigest(),
    "env_keys": env_keys,
    "env_url_hosts": url_hosts,
    "bundle_path": urllib.parse.urlparse(bundle_url).path,
    "bundle_bytes": len(bundle_raw),
    "bundle_sha256": hashlib.sha256(bundle_raw).hexdigest(),
    "transport_counts": transport_counts,
    "target_route_occurrences": len(route_positions),
    "operation_id_occurrences": len(operation_positions),
    "target_windows": windows,
}, sort_keys=True, separators=(",", ":")))
