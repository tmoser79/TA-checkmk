#!/usr/bin/env python3
"""Eventgen coverage: every supported sourcetype has a disabled sample stanza."""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
import ta_checkmk_lib  # noqa: E402

SUPPORTED_SOURCETYPES = {
    "checkmk:alert",
    "checkmk:ec",
    "checkmk:status",
    "checkmk:history",
    "checkmk:notify",
    "checkmk:mknotifyd",
    "checkmk:cmc",
    "checkmk:web",
    "checkmk:security",
    "checkmk:eventconsole",
    "checkmk:alerts_handler",
    "checkmk:dcd",
    "checkmk:liveproxyd",
    "apache:access:combined",
    "apache:error",
}


def parse_eventgen(path: Path) -> dict[str, dict[str, str]]:
    stanzas: dict[str, dict[str, str]] = {}
    current = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            stanzas[current] = {}
            continue
        if current is None or "=" not in line:
            continue
        key, _, value = line.partition("=")
        stanzas[current][key.strip()] = value.strip()
    return stanzas


class EventgenConfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.stanzas = parse_eventgen(ROOT / "default" / "eventgen.conf")
        cls.samples = ROOT / "samples"

    def test_disabled_globally(self) -> None:
        self.assertIn("global", self.stanzas)
        self.assertEqual(self.stanzas["global"].get("disabled"), "true")
        self.assertNotIn("httpeventServers", json.dumps(self.stanzas))

    def test_no_embedded_tokens(self) -> None:
        text = (ROOT / "default" / "eventgen.conf").read_text(encoding="utf-8")
        self.assertNotIn("Authorization", text)
        self.assertNotRegex(text, r"key\"\s*:\s*\"[0-9a-fA-F-]{8,}")

    def test_every_sample_stanza_has_file(self) -> None:
        for name, settings in self.stanzas.items():
            if name == "global":
                continue
            sample = self.samples / name
            self.assertTrue(sample.is_file(), f"missing sample file for [{name}]")
            self.assertGreater(sample.stat().st_size, 0)
            self.assertIn("sourcetype", settings)

    def test_all_supported_sourcetypes_have_stanzas(self) -> None:
        found = {
            settings["sourcetype"]
            for name, settings in self.stanzas.items()
            if name != "global" and "sourcetype" in settings
        }
        self.assertEqual(SUPPORTED_SOURCETYPES, found)

    def test_json_samples_are_json_lines(self) -> None:
        for name in ("checkmk_alert.sample", "checkmk_ec.sample", "checkmk_status.sample"):
            for line in (self.samples / name).read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                payload = json.loads(line)
                self.assertEqual(payload.get("app"), "checkmk")
                self.assertIn("dest", payload)
                self.assertIn("vendor_severity", payload)

    def test_timestamp_tokens_have_no_capture_group(self) -> None:
        # Eventgen replaces capture group 1 and keeps the rest of the match.
        for name, settings in self.stanzas.items():
            for key, value in settings.items():
                if not key.endswith(".replacementType") or value != "timestamp":
                    continue
                token_key = key[: -len("replacementType")] + "token"
                token = settings[token_key]
                self.assertEqual(
                    re.compile(token).groups,
                    0,
                    f"[{name}] {token_key} must replace the whole timestamp",
                )

    def test_history_timestamp_token_keeps_single_brackets(self) -> None:
        settings = self.stanzas["checkmk_history.sample"]
        token = re.compile(settings["token.0.token"])
        line = "[1730800002] HOST ALERT: web02;UNREACHABLE;SOFT;1;No route to host"
        match = token.search(line)
        self.assertIsNotNone(match)
        assert match is not None
        replaced = line[: match.start()] + "[1793999560]" + line[match.end() :]
        self.assertEqual(
            replaced,
            "[1793999560] HOST ALERT: web02;UNREACHABLE;SOFT;1;No route to host",
        )
        parsed = ta_checkmk_lib.parse_history_line(replaced)
        assert parsed is not None
        self.assertEqual(parsed["dest"], "web02")
        self.assertEqual(parsed["vendor_severity"], "UNREACHABLE")
        self.assertEqual(parsed["history_epoch"], "1793999560")

    def test_history_sample_parses(self) -> None:
        lines = (self.samples / "checkmk_history.sample").read_text(encoding="utf-8").splitlines()
        parsed = [ta_checkmk_lib.parse_history_line(line) for line in lines if line.strip()]
        self.assertTrue(all(parsed))
        self.assertEqual(parsed[0]["log_type"], "SERVICE ALERT")
        self.assertEqual(parsed[0]["dest"], "@@host")
        self.assertEqual(parsed[0]["signature"], "@@service")
        self.assertEqual(parsed[1]["log_type"], "HOST ALERT")
        hosts = (self.samples / "checkmk_hosts.list").read_text(encoding="utf-8").splitlines()
        services = (self.samples / "checkmk_services.list").read_text(encoding="utf-8").splitlines()
        filled = lines[0].replace("@@host", hosts[0]).replace("@@service", services[0])
        event = ta_checkmk_lib.parse_history_line(filled)
        assert event is not None
        self.assertEqual(event["dest"], "web01")
        self.assertEqual(event["signature"], "Filesystem /")
        self.assertEqual(event["severity"], "critical")

    def test_replacement_lists_are_nonempty(self) -> None:
        for name in ("checkmk_hosts.list", "checkmk_services.list", "checkmk_contacts.list"):
            rows = [
                line
                for line in (self.samples / name).read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertGreaterEqual(len(rows), 3, name)

    def test_python_log_samples_have_timestamps(self) -> None:
        stamp = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")
        for name in (
            "checkmk_notify.sample",
            "checkmk_mknotifyd.sample",
            "checkmk_cmc.sample",
            "checkmk_web.sample",
            "checkmk_security.sample",
            "checkmk_eventconsole.sample",
            "checkmk_alerts_handler.sample",
            "checkmk_dcd.sample",
            "checkmk_liveproxyd.sample",
        ):
            first = (self.samples / name).read_text(encoding="utf-8").splitlines()[0]
            self.assertRegex(first, stamp, name)


if __name__ == "__main__":
    unittest.main()
