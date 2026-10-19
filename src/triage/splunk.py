"""Load Splunk alerts from disk and convert them into Alert objects.

Supported input formats:
  * A Splunk webhook alert action payload: {"search_name": ..., "sid": ..., "result": {...}}
  * Splunk search export (one JSON object per line): {"preview": false, "result": {...}}
  * A JSON list of either of the above
  * A bare result dictionary with no wrapper
"""

import json
from pathlib import Path

from triage.extract import extract_indicators
from triage.models import Alert

# Splunk fields vary by data source. For each common field, try these names in order.
# Names follow the Splunk Common Information Model (CIM) where possible.
FIELD_MAP = {
    "host": ["dest_host", "host", "ComputerName"],
    "user": ["user", "user_name", "src_user", "Account_Name"],
    "src": ["src_ip", "src", "source_ip"],
    "dest": ["dest_ip", "dest", "destination_ip"],
}


def _first_value(result: dict, keys: list[str]) -> str | None:
    """Return the first non-empty field from `keys`. Multivalue fields use their first entry."""
    for key in keys:
        value = result.get(key)
        if isinstance(value, list):
            value = value[0] if value else None
        if value not in (None, ""):
            return str(value)
    return None


def load_payloads(path: Path) -> list[tuple[str, dict]]:
    """Read one file or every .json file in a directory.

    Returns (source_label, payload) pairs so each alert can be traced back to its file.
    """
    files = sorted(path.glob("*.json")) if path.is_dir() else [path]
    payloads: list[tuple[str, dict]] = []

    for file in files:
        text = file.read_text(encoding="utf-8").strip()
        if not text:
            continue
        try:
            data = json.loads(text)
            items = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            # Not a single JSON document, so try one JSON object per line (Splunk export).
            items = [json.loads(line) for line in text.splitlines() if line.strip()]

        for index, item in enumerate(items):
            label = file.stem if len(items) == 1 else f"{file.stem}-{index + 1}"
            payloads.append((label, item))

    return payloads


def parse_payload(label: str, payload: dict) -> Alert:
    """Convert one Splunk payload into an Alert."""
    # Webhook and export formats wrap the event fields in "result"; a bare dict does not.
    result = payload.get("result", payload)
    name = payload.get("search_name") or result.get("search_name") or "Unnamed alert"

    return Alert(
        alert_id=payload.get("sid") or label,
        name=name,
        time=_first_value(result, ["_time", "time"]),
        host=_first_value(result, FIELD_MAP["host"]),
        user=_first_value(result, FIELD_MAP["user"]),
        src=_first_value(result, FIELD_MAP["src"]),
        dest=_first_value(result, FIELD_MAP["dest"]),
        raw=payload,
        indicators=extract_indicators(result),
    )


def load_alerts(path: Path) -> list[Alert]:
    return [parse_payload(label, payload) for label, payload in load_payloads(path)]
