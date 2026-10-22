#!/usr/bin/env python3
"""Check OSS incident HTTP capabilities on an already isolated test instance."""

import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def request(base_url, path, authorization=None):
    headers = {"Accept": "application/json"}
    if authorization is not None:
        headers["Authorization"] = authorization
    req = urllib.request.Request(base_url + path, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def expect(base_url, path, status, authorization=None):
    actual, body = request(base_url, path, authorization)
    if actual != status:
        raise RuntimeError(f"GET {path}: expected HTTP {status}, got {actual}")
    print(f"PASS GET {path}: HTTP {actual}")
    return json.loads(body) if status == 200 else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_url", help="URL of the disposable instance, including any base URI")
    parser.add_argument("--org", default="default")
    parser.add_argument("--wait-seconds", type=int, default=90)
    args = parser.parse_args()
    email = os.environ.get("ZO_SMOKE_EMAIL")
    password = os.environ.get("ZO_SMOKE_PASSWORD")
    if not email or not password:
        parser.error("set ZO_SMOKE_EMAIL and ZO_SMOKE_PASSWORD for the test instance")
    if args.wait_seconds < 0:
        parser.error("--wait-seconds must be nonnegative")
    parsed_url = urllib.parse.urlsplit(args.base_url)
    if parsed_url.scheme not in ("http", "https") or not parsed_url.netloc:
        parser.error("base_url must be an HTTP or HTTPS URL")
    if parsed_url.username or parsed_url.password or parsed_url.query or parsed_url.fragment:
        parser.error("base_url must not contain credentials, a query, or a fragment")
    base_url = args.base_url.rstrip("/")
    deadline = time.monotonic() + args.wait_seconds
    while True:
        try:
            status, _ = request(base_url, "/healthz")
            if status == 200:
                break
        except (OSError, urllib.error.URLError):
            pass
        if time.monotonic() >= deadline:
            raise RuntimeError("test instance did not become healthy before the deadline")
        time.sleep(1)
    print("PASS GET /healthz: HTTP 200")
    status, html = request(base_url, "/web/")
    if status != 200 or b"<html" not in html.lower():
        raise RuntimeError(f"GET /web/: expected an HTML page, got HTTP {status}")
    scripts = re.findall(r'<script\b[^>]*\bsrc=[\"\']([^\"\']+)[\"\']', html.decode())
    bundle = next((src for src in scripts if "/assets/" in src and src.endswith(".js")), None)
    if bundle is None:
        raise RuntimeError("web page does not reference a built JavaScript bundle")
    bundle_url = urllib.parse.urljoin(base_url + "/web/", bundle)
    if not bundle_url.startswith(base_url + "/"):
        raise RuntimeError("web bundle URL is outside the test instance base URL")
    bundle_path = bundle_url[len(base_url):]
    status, data = request(base_url, bundle_path)
    if status != 200 or not data or b"<html" in data[:200].lower():
        raise RuntimeError(f"GET {bundle_path}: expected a JavaScript bundle, got HTTP {status}")
    print("PASS web HTML and built JavaScript bundle")
    org = urllib.parse.quote(args.org, safe="")
    incidents = f"/api/v2/{org}/alerts/incidents"
    authorization = "Basic " + base64.b64encode(f"{email}:{password}".encode()).decode()
    expect(base_url, incidents, 401)
    config = expect(base_url, f"/api/{org}/config", 200, authorization)
    for key, value in (
        ("incidents_enabled", True),
        ("incidents_ai_enabled", False),
        ("incidents_topology_enabled", False),
    ):
        if config.get(key) is not value:
            raise RuntimeError(f"authenticated config: expected {key}={value}")
    print("PASS OSS capabilities: incidents enabled, AI and topology disabled")
    listing = expect(base_url, incidents + "?limit=10&offset=0", 200, authorization)
    if not isinstance(listing.get("incidents"), list) or not isinstance(listing.get("total"), int):
        raise RuntimeError("incident list has an unexpected response shape")
    stats = expect(base_url, incidents + "/stats", 200, authorization)
    if not isinstance(stats.get("total_incidents"), int):
        raise RuntimeError("incident statistics have an unexpected response shape")
    for query in ("limit=0", "limit=501", "status=invalid", "offset=-1"):
        expect(base_url, incidents + "?" + query, 400, authorization)
    print("HTTP smoke passed; alert lifecycle, notifications, UI, and restart acceptance remain separate checks.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, urllib.error.URLError) as error:
        print(f"FAIL {error}", file=sys.stderr)
        sys.exit(1)
