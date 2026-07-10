#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import html.parser
import json
import urllib.parse
import urllib.request

ROOT = "https://app.codacy.com/"
ALLOWED_HOSTS = {"app.codacy.com", "api.codacy.com"}
MAX_HTML = 1_000_000


class Collector(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.assets = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "script" and values.get("src"):
            self.assets.append(("script", values["src"]))
        if tag == "link" and values.get("href") and values.get("rel") in {
            "modulepreload", "preload", "stylesheet"
        }:
            self.assets.append(("link:" + values.get("rel", ""), values["href"]))


req = urllib.request.Request(
    ROOT,
    headers={"Accept": "text/html", "User-Agent": "Codacy-H1-safe-validation/1.5"},
)
with urllib.request.urlopen(req, timeout=30) as response:
    status = int(response.status)
    content_type = response.headers.get("Content-Type", "")
    raw = response.read(MAX_HTML + 1)
if len(raw) > MAX_HTML:
    raise SystemExit("HTML exceeded safety limit")

collector = Collector()
collector.feed(raw.decode("utf-8", "replace"))
assets = []
for kind, value in collector.assets:
    absolute = urllib.parse.urljoin(ROOT, value)
    parsed = urllib.parse.urlparse(absolute)
    assets.append({
        "kind": kind,
        "host": parsed.hostname,
        "path": parsed.path,
        "query_present": bool(parsed.query),
        "in_scope_host": parsed.scheme == "https" and parsed.hostname in ALLOWED_HOSTS,
    })

print("CODACY_FRONTEND_INVENTORY=" + json.dumps({
    "status": status,
    "content_type": content_type,
    "bytes": len(raw),
    "sha256": hashlib.sha256(raw).hexdigest(),
    "assets": assets,
}, sort_keys=True, separators=(",", ":")))
