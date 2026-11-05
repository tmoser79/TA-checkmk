#!/usr/bin/env python3
"""Optional Checkmk REST modular input.

Polls /check_mk/api/1.0 for current host and service states and writes CIM-shaped
JSON events. TLS verification is on by default. Intended for a Heavy Forwarder.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Dict, Iterable, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ta_checkmk_lib import map_severity  # noqa: E402

SCHEME = """<scheme>
  <title>Checkmk REST status</title>
  <description>Poll Checkmk REST API for host and service states.</description>
  <use_external_validation>true</use_external_validation>
  <streaming_mode>simple</streaming_mode>
  <endpoint>
    <args>
      <arg name="api_url">
        <title>Checkmk API base URL</title>
        <description>Example: https://checkmk.example.com/mysite</description>
        <required_on_create>true</required_on_create>
      </arg>
      <arg name="username">
        <title>Automation user</title>
        <required_on_create>true</required_on_create>
      </arg>
      <arg name="secret">
        <title>Automation secret</title>
        <required_on_create>true</required_on_create>
      </arg>
      <arg name="only_problems">
        <title>Only non-OK states</title>
        <required_on_create>false</required_on_create>
      </arg>
      <arg name="verify_tls">
        <title>Verify TLS</title>
        <required_on_create>false</required_on_create>
      </arg>
    </args>
  </endpoint>
</scheme>
"""

TRUTHY = {"1", "true", "yes", "on"}


def log(message: str) -> None:
    sys.stderr.write(message.rstrip() + "\n")


def is_true(value: Optional[str], default: bool = True) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in TRUTHY


def ssl_context(verify: bool) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def parse_input_xml(payload: str) -> List[Dict[str, str]]:
    root = ET.fromstring(payload)
    stanzas = []
    for stanza in root.findall("./configuration/stanza"):
        item = {"name": stanza.get("name", "")}
        for param in stanza.findall("param"):
            name = param.get("name")
            if name:
                item[name] = (param.text or "").strip()
        stanzas.append(item)
    return stanzas


def api_get(base_url: str, path: str, username: str, secret: str, verify: bool) -> dict:
    url = base_url.rstrip("/") + "/check_mk/api/1.0" + path
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {username} {secret}",
            "Accept": "application/json",
        },
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=60, context=ssl_context(verify)) as response:
        return json.loads(response.read().decode("utf-8"))


def service_state_name(state: object) -> str:
    mapping = {0: "OK", 1: "WARN", 2: "CRIT", 3: "UNKNOWN", "0": "OK", "1": "WARN", "2": "CRIT", "3": "UNKNOWN"}
    return mapping.get(state, str(state))


def host_state_name(state: object) -> str:
    mapping = {0: "UP", 1: "DOWN", 2: "UNREACH", "0": "UP", "1": "DOWN", "2": "UNREACH"}
    return mapping.get(state, str(state))


def emit(event: dict) -> None:
    sys.stdout.write(json.dumps(event, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def iter_collection(payload: dict) -> Iterable[dict]:
    value = payload.get("value")
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                yield item


def poll_stanza(stanza: Dict[str, str]) -> None:
    api_url = stanza.get("api_url", "").rstrip("/")
    username = stanza.get("username", "")
    secret = stanza.get("secret", "")
    verify = is_true(stanza.get("verify_tls"), True)
    only_problems = is_true(stanza.get("only_problems"), True)
    if not api_url or not username or not secret:
        log("checkmk_rest: api_url, username, and secret are required")
        return

    now = int(time.time())
    services = api_get(
        api_url,
        "/domain-types/service/collections/all?columns=host_name&columns=description&columns=state&columns=plugin_output&columns=check_command",
        username,
        secret,
        verify,
    )
    for item in iter_collection(services):
        ext = item.get("extensions") or item
        state = ext.get("state")
        vendor = service_state_name(state)
        if only_problems and vendor == "OK":
            continue
        severity, severity_id = map_severity(vendor)
        emit(
            {
                "app": "checkmk",
                "vendor_product": "Checkmk",
                "type": "alert",
                "what": "SERVICE",
                "dest": ext.get("host_name"),
                "dest_host": ext.get("host_name"),
                "signature": ext.get("description"),
                "signature_id": ext.get("check_command"),
                "vendor_severity": vendor,
                "severity": severity,
                "severity_id": severity_id,
                "description": ext.get("plugin_output") or ext.get("description"),
                "id": f"{ext.get('host_name')}:{ext.get('description')}:{now}",
                "site": urllib.parse.urlparse(api_url).path.strip("/"),
            }
        )

    hosts = api_get(
        api_url,
        "/domain-types/host/collections/all?columns=name&columns=state&columns=plugin_output&columns=address",
        username,
        secret,
        verify,
    )
    for item in iter_collection(hosts):
        ext = item.get("extensions") or item
        state = ext.get("state")
        vendor = host_state_name(state)
        if only_problems and vendor == "UP":
            continue
        severity, severity_id = map_severity(vendor)
        emit(
            {
                "app": "checkmk",
                "vendor_product": "Checkmk",
                "type": "alert",
                "what": "HOST",
                "dest": ext.get("name"),
                "dest_host": ext.get("name"),
                "dest_ip": ext.get("address"),
                "signature": "Host Check",
                "vendor_severity": vendor,
                "severity": severity,
                "severity_id": severity_id,
                "description": ext.get("plugin_output") or vendor,
                "id": f"{ext.get('name')}:host:{now}",
                "site": urllib.parse.urlparse(api_url).path.strip("/"),
            }
        )


def validate(payload: str) -> int:
    try:
        stanzas = parse_input_xml(payload)
    except ET.ParseError as exc:
        log(f"checkmk_rest: invalid XML: {exc}")
        return 1
    for stanza in stanzas:
        if not stanza.get("api_url"):
            log("checkmk_rest: api_url is required")
            return 1
        if not re.match(r"^https?://", stanza["api_url"], re.I):
            log("checkmk_rest: api_url must start with http:// or https://")
            return 1
        if not stanza.get("username") or not stanza.get("secret"):
            log("checkmk_rest: username and secret are required")
            return 1
    return 0


def run() -> int:
    payload = sys.stdin.read()
    try:
        stanzas = parse_input_xml(payload)
    except ET.ParseError as exc:
        log(f"checkmk_rest: invalid XML: {exc}")
        return 1
    for stanza in stanzas:
        try:
            poll_stanza(stanza)
        except urllib.error.HTTPError as exc:
            log(f"checkmk_rest: HTTP {exc.code} for {stanza.get('name')}")
            return 1
        except urllib.error.URLError as exc:
            log(f"checkmk_rest: {exc.reason}")
            return 1
    return 0


def main(argv: List[str]) -> int:
    if len(argv) > 1:
        if argv[1] == "--scheme":
            sys.stdout.write(SCHEME)
            return 0
        if argv[1] == "--validate-arguments":
            return validate(sys.stdin.read())
    return run()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
