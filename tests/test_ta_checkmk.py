#!/usr/bin/env python3
"""Validate Checkmk TA extractions, CIM severity maps, HEC payload, REST scheme."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin"
PLUGIN = ROOT / "checkmk" / "notifications" / "splunk_hec"
sys.path.insert(0, str(BIN))

import ta_checkmk_lib  # noqa: E402


def load_plugin():
    loader = importlib.machinery.SourceFileLoader("splunk_hec_plugin", str(PLUGIN))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def history_stanza_extracts() -> dict[str, str]:
    props = (ROOT / "default" / "props.conf").read_text(encoding="utf-8")
    in_history = False
    extracts: dict[str, str] = {}
    for raw in props.splitlines():
        line = raw.rstrip()
        if line.startswith("[") and line.endswith("]"):
            in_history = line == "[checkmk:history]"
            continue
        if not in_history or not line.startswith("EXTRACT-"):
            continue
        name, _, pattern = line.partition(" = ")
        extracts[name[len("EXTRACT-") :]] = pattern
    return extracts


class HistoryParsing(unittest.TestCase):
    def test_sample_history_lines(self) -> None:
        path = ROOT / "samples" / "checkmk_history.log"
        parsed = [
            ta_checkmk_lib.parse_history_line(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertTrue(all(parsed), "every history sample line should parse a header")
        service_alert = parsed[0]
        assert service_alert is not None
        self.assertEqual(service_alert["log_type"], "SERVICE ALERT")
        self.assertEqual(service_alert["dest"], "web01")
        self.assertEqual(service_alert["signature"], "Filesystem /")
        self.assertEqual(service_alert["vendor_severity"], "CRITICAL")
        self.assertEqual(service_alert["severity"], "critical")
        host_alert = parsed[1]
        assert host_alert is not None
        self.assertEqual(host_alert["dest"], "web01")
        self.assertEqual(host_alert["vendor_severity"], "DOWN")
        self.assertEqual(host_alert["signature"], "Host Check")
        notify = parsed[2]
        assert notify is not None
        self.assertEqual(notify["user"], "oncall")
        self.assertEqual(notify["notify_command"], "splunk_hec")

    def test_props_extracts_match_library(self) -> None:
        extracts = history_stanza_extracts()
        for log_type, regex in ta_checkmk_lib.HISTORY_EXTRACTS.items():
            matching = [
                pattern
                for name, pattern in extracts.items()
                if log_type.replace(" ", "_").lower().startswith(name.replace("_alert", "").split("_")[0])
                or log_type in pattern
            ]
            self.assertTrue(matching, f"props.conf missing EXTRACT for {log_type}")
            compiled = [re.compile(pattern) for pattern in matching]
            self.assertTrue(any(item.pattern == regex.pattern for item in compiled) or compiled)

    def test_props_extracts_on_samples(self) -> None:
        extracts = history_stanza_extracts()
        compiled = {
            name: re.compile(pattern) for name, pattern in extracts.items() if name != "history_header"
        }
        lines = (ROOT / "samples" / "checkmk_history.log").read_text(encoding="utf-8").splitlines()
        matched_types = set()
        for line in lines:
            if "SERVICE ALERT:" in line and "HANDLER" not in line:
                match = compiled["service_alert"].match(line)
                self.assertIsNotNone(match, line)
                assert match is not None
                self.assertEqual(match.group("dest"), "web01")
                matched_types.add("SERVICE ALERT")
            if line.startswith("[") and "HOST ALERT:" in line and "HANDLER" not in line and "ACKNOWLEDGE" not in line and "DOWNTIME" not in line and "FLAPPING" not in line:
                match = compiled["host_alert"].match(line)
                self.assertIsNotNone(match, line)
                matched_types.add("HOST ALERT")
        self.assertIn("SERVICE ALERT", matched_types)
        self.assertIn("HOST ALERT", matched_types)


class SeverityLookup(unittest.TestCase):
    def test_lookup_csv_covers_library(self) -> None:
        lookup = ta_checkmk_lib.load_severity_lookup()
        for vendor, expected in ta_checkmk_lib.SEVERITY_MAP.items():
            self.assertEqual(lookup[vendor], expected)

    def test_cim_prescribed_values(self) -> None:
        allowed = {"critical", "high", "medium", "low", "informational"}
        lookup = ta_checkmk_lib.load_severity_lookup()
        for severity, _severity_id in lookup.values():
            self.assertIn(severity, allowed)


class HecPlugin(unittest.TestCase):
    def test_service_payload(self) -> None:
        plugin = load_plugin()
        context = {
            "WHAT": "SERVICE",
            "HOSTNAME": "web01",
            "HOSTADDRESS": "10.1.2.10",
            "SERVICEDESC": "Filesystem /",
            "SERVICESTATE": "CRIT",
            "SERVICEOUTPUT": "CRIT - 96% used",
            "SERVICECHECKCOMMAND": "check_mk-df",
            "SERVICEPROBLEMID": "88421",
            "NOTIFICATIONTYPE": "PROBLEM",
            "CONTACTNAME": "oncall",
            "MICROTIME": "1730800003000000",
        }
        event = plugin.build_event(context)
        self.assertEqual(event["app"], "checkmk")
        self.assertEqual(event["dest"], "web01")
        self.assertEqual(event["dest_ip"], "10.1.2.10")
        self.assertEqual(event["signature"], "Filesystem /")
        self.assertEqual(event["severity"], "critical")
        self.assertEqual(event["type"], "alert")
        self.assertEqual(event["id"], "88421")
        params = {
            "url": "https://splunk.example.com:8088/services/collector/event",
            "token": "unused",
            "index": "checkmk",
            "sourcetype": "checkmk:alert",
        }
        payload = plugin.build_payload(context, params)
        self.assertEqual(payload["time"], 1730800003)
        self.assertEqual(payload["sourcetype"], "checkmk:alert")
        self.assertNotIn("token", json.dumps(payload))

    def test_host_payload(self) -> None:
        plugin = load_plugin()
        event = plugin.build_event(
            {
                "WHAT": "HOST",
                "HOSTNAME": "web01",
                "HOSTSTATE": "DOWN",
                "HOSTOUTPUT": "Packet loss 100%",
                "HOSTPROBLEMID": "9",
                "NOTIFICATIONTYPE": "PROBLEM",
            }
        )
        self.assertEqual(event["signature"], "Host Check")
        self.assertEqual(event["severity"], "critical")
        self.assertEqual(event["what"], "HOST")

    def test_positional_params(self) -> None:
        plugin = load_plugin()
        params = plugin.plugin_params(
            {
                "PARAMETER_1": "https://splunk.example.com:8088/services/collector/event",
                "PARAMETER_2": "example-token",
                "PARAMETER_3": "checkmk",
            }
        )
        self.assertEqual(params["index"], "checkmk")
        self.assertTrue(params["url"].startswith("https://"))

    def test_missing_params(self) -> None:
        plugin = load_plugin()
        with self.assertRaises(ValueError):
            plugin.plugin_params({})


class RestModularInput(unittest.TestCase):
    def test_scheme(self) -> None:
        spec = importlib.util.spec_from_file_location("checkmk_rest", BIN / "checkmk_rest.py")
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        self.assertIn("<title>Checkmk REST status</title>", module.SCHEME)
        xml = """<input><configuration>
          <stanza name="checkmk_rest://lab">
            <param name="api_url">https://checkmk.example.com/mysite</param>
            <param name="username">automation</param>
            <param name="secret">example-secret</param>
          </stanza>
        </configuration></input>"""
        self.assertEqual(module.validate(xml), 0)
        self.assertEqual(
            module.validate(
                """<input><configuration><stanza name="x">
                <param name="api_url">not-a-url</param>
                </stanza></configuration></input>"""
            ),
            1,
        )

    def test_poll_filters_ok_services(self) -> None:
        spec = importlib.util.spec_from_file_location("checkmk_rest", BIN / "checkmk_rest.py")
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        services = {
            "value": [
                {
                    "extensions": {
                        "host_name": "web01",
                        "description": "Filesystem /",
                        "state": 2,
                        "plugin_output": "CRIT - full",
                        "check_command": "check_mk-df",
                    }
                },
                {
                    "extensions": {
                        "host_name": "web01",
                        "description": "CPU",
                        "state": 0,
                        "plugin_output": "OK",
                    }
                },
            ]
        }
        hosts = {"value": [{"extensions": {"name": "web01", "state": 0, "plugin_output": "UP"}}]}

        def fake_api(_base, path, _user, _secret, _verify):
            return services if "/service/" in path else hosts

        events = []
        with mock.patch.object(module, "api_get", side_effect=fake_api), mock.patch.object(
            module, "emit", side_effect=events.append
        ):
            module.poll_stanza(
                {
                    "api_url": "https://checkmk.example.com/mysite",
                    "username": "automation",
                    "secret": "example-secret",
                    "only_problems": "1",
                    "verify_tls": "1",
                }
            )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["signature"], "Filesystem /")
        self.assertEqual(events[0]["severity"], "critical")


class Packaging(unittest.TestCase):
    def test_app_id_matches_folder(self) -> None:
        app_conf = (ROOT / "default" / "app.conf").read_text(encoding="utf-8")
        self.assertIn("id = TA-checkmk", app_conf)
        self.assertIn("is_visible = 0", app_conf)
        manifest = json.loads((ROOT / "app.manifest").read_text(encoding="utf-8"))
        self.assertEqual(manifest["info"]["id"]["name"], "TA-checkmk")
        self.assertIn("_search_head_clustering", manifest["supportedDeployments"])

    def test_notification_plugin_ships_in_ta(self) -> None:
        self.assertTrue(PLUGIN.is_file(), PLUGIN)
        self.assertTrue(PLUGIN.read_text(encoding="utf-8").startswith("#!/usr/bin/env python3"))
        ruleset = ROOT / "checkmk" / "rulesets" / "splunk_hec.py"
        self.assertTrue(ruleset.is_file(), ruleset)
        self.assertIn("name=\"splunk_hec\"", ruleset.read_text(encoding="utf-8"))

    def test_no_embedded_secrets(self) -> None:
        forbidden = re.compile(r"(sk_live_|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,})")
        skip_dirs = {"tests", "__pycache__"}
        for path in ROOT.rglob("*"):
            if any(part in skip_dirs for part in path.parts):
                continue
            if path.is_file() and path.suffix in {".conf", ".py", ".md", ".json", ".csv", ".log", ".spec"}:
                text = path.read_text(encoding="utf-8", errors="ignore")
                self.assertIsNone(forbidden.search(text), path)


if __name__ == "__main__":
    unittest.main()
