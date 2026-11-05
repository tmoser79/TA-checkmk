#!/usr/bin/env python3
"""Shared Checkmk field helpers for the Splunk TA.

Used by the optional REST modular input and by unit tests. Severity labels
follow the CIM Alerts prescribed values.
"""

from __future__ import annotations

import csv
import os
import re
from typing import Dict, Optional

SEVERITY_MAP = {
    "CRITICAL": ("critical", "5"),
    "CRIT": ("critical", "5"),
    "DOWN": ("critical", "5"),
    "UNREACHABLE": ("high", "4"),
    "UNREACH": ("high", "4"),
    "WARNING": ("medium", "3"),
    "WARN": ("medium", "3"),
    "UNKNOWN": ("low", "2"),
    "OK": ("informational", "1"),
    "UP": ("informational", "1"),
    "RECOVERY": ("informational", "1"),
}

STATE_FROM_NUMERIC = {
    "0": "OK",
    "1": "WARNING",
    "2": "CRITICAL",
    "3": "UNKNOWN",
}

HOST_STATE_FROM_NUMERIC = {
    "0": "UP",
    "1": "DOWN",
    "2": "UNREACHABLE",
}

HISTORY_EXTRACTS = {
    "SERVICE ALERT": re.compile(
        r"^\[\d+\]\s+SERVICE ALERT:\s+(?P<dest>[^;]+);(?P<signature>[^;]+);"
        r"(?P<vendor_severity>[^;]+);(?P<state_type>[^;]+);(?P<attempt>[^;]+);"
        r"(?P<description>.*)$"
    ),
    "HOST ALERT": re.compile(
        r"^\[\d+\]\s+HOST ALERT:\s+(?P<dest>[^;]+);(?P<vendor_severity>[^;]+);"
        r"(?P<state_type>[^;]+);(?P<attempt>[^;]+);(?P<description>.*)$"
    ),
    "SERVICE NOTIFICATION": re.compile(
        r"^\[\d+\]\s+SERVICE NOTIFICATION:\s+(?P<user>[^;]+);(?P<dest>[^;]+);"
        r"(?P<signature>[^;]+);(?P<vendor_severity>[^;]+);(?P<notify_command>[^;]+);"
        r"(?P<description>.*)$"
    ),
    "HOST NOTIFICATION": re.compile(
        r"^\[\d+\]\s+HOST NOTIFICATION:\s+(?P<user>[^;]+);(?P<dest>[^;]+);"
        r"(?P<vendor_severity>[^;]+);(?P<notify_command>[^;]+);(?P<description>.*)$"
    ),
    "SERVICE DOWNTIME ALERT": re.compile(
        r"^\[\d+\]\s+SERVICE DOWNTIME ALERT:\s+(?P<dest>[^;]+);(?P<signature>[^;]+);"
        r"(?P<state_type>[^;]+);(?P<comment>.*)$"
    ),
    "HOST DOWNTIME ALERT": re.compile(
        r"^\[\d+\]\s+HOST DOWNTIME ALERT:\s+(?P<dest>[^;]+);(?P<state_type>[^;]+);"
        r"(?P<comment>.*)$"
    ),
    "SERVICE ACKNOWLEDGE ALERT": re.compile(
        r"^\[\d+\]\s+SERVICE ACKNOWLEDGE ALERT:\s+(?P<dest>[^;]+);(?P<signature>[^;]+);"
        r"(?P<state_type>[^;]+);(?P<user>[^;]+);(?P<comment>.*)$"
    ),
    "HOST ACKNOWLEDGE ALERT": re.compile(
        r"^\[\d+\]\s+HOST ACKNOWLEDGE ALERT:\s+(?P<dest>[^;]+);(?P<state_type>[^;]+);"
        r"(?P<user>[^;]+);(?P<comment>.*)$"
    ),
}

HEADER_RE = re.compile(
    r"^\[(?P<history_epoch>\d+)\]\s+(?P<log_type>[A-Z][A-Z0-9 ]+?)(?::\s+|$)"
)


def map_severity(vendor_severity: Optional[str]) -> tuple[str, str]:
    if not vendor_severity:
        return "informational", "1"
    key = vendor_severity.strip().upper()
    if key in SEVERITY_MAP:
        return SEVERITY_MAP[key]
    if key.startswith("CRIT"):
        return "critical", "5"
    if key.startswith("WARN"):
        return "medium", "3"
    return "informational", "1"


def vendor_severity_from_state(state: Optional[str], what: str) -> str:
    if not state:
        return "UNKNOWN"
    if state.isdigit():
        table = HOST_STATE_FROM_NUMERIC if what == "HOST" else STATE_FROM_NUMERIC
        return table.get(state, "UNKNOWN")
    return state


def parse_history_line(line: str) -> Optional[Dict[str, str]]:
    line = line.rstrip("\n")
    header = HEADER_RE.match(line)
    if not header:
        return None
    fields = header.groupdict()
    log_type = fields["log_type"]
    for prefix, regex in HISTORY_EXTRACTS.items():
        if log_type == prefix or log_type.startswith(prefix):
            match = regex.match(line)
            if match:
                fields.update({k: v for k, v in match.groupdict().items() if v is not None})
                break
    if "signature" not in fields and log_type.startswith("HOST"):
        fields["signature"] = "Host Check"
    vendor = fields.get("vendor_severity")
    severity, severity_id = map_severity(vendor)
    fields["severity"] = severity
    fields["severity_id"] = severity_id
    fields["app"] = "checkmk"
    fields["vendor_product"] = "Checkmk"
    return fields


def load_severity_lookup(path: Optional[str] = None) -> Dict[str, tuple[str, str]]:
    if path is None:
        path = os.path.join(
            os.path.dirname(__file__), "..", "lookups", "checkmk_severity_lookup.csv"
        )
    mapping: Dict[str, tuple[str, str]] = {}
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            mapping[row["vendor_severity"].upper()] = (row["severity"], row["severity_id"])
    return mapping
