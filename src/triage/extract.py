"""Find indicators of compromise (IPs, URLs, domains, file hashes) in alert fields."""

import ipaddress
import re
from urllib.parse import urlsplit

from triage.models import Indicator

# Defanged indicators are written so they can't be clicked, e.g. hxxp://evil[.]com.
# Refanging turns them back into real values before extraction.
_REFANG_RULES = [
    # A function replacement so "HXXPS" becomes "https", not "httpS".
    (re.compile(r"hxxp(s?)", re.IGNORECASE), lambda m: "http" + m.group(1).lower()),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}"), "."),
    (re.compile(r"\[:\]"), ":"),
]

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Word boundaries stop a 64-character SHA256 from also matching as a 32-character MD5.
_HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")

# Splunk internal fields (e.g. _bkt, _cd) can contain hex strings that look like hashes.
# Skip every underscore field except _raw, which holds the original event text.
_SCANNED_INTERNAL_FIELDS = {"_raw"}


def refang(text: str) -> str:
    for pattern, replacement in _REFANG_RULES:
        text = pattern.sub(replacement, text)
    return text


def defang(value: str) -> str:
    """Make a URL or domain unclickable for reports. Inverse of refang."""
    return value.replace("http", "hxxp").replace(".", "[.]")


def _collect_strings(value, out: list[str]) -> None:
    """Walk nested lists/dicts and collect every string value."""
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, list):
        for item in value:
            _collect_strings(item, out)
    elif isinstance(value, dict):
        for item in value.values():
            _collect_strings(item, out)


def _is_valid_ip(candidate: str) -> bool:
    try:
        ipaddress.IPv4Address(candidate)
        return True
    except ValueError:
        return False


def extract_from_text(text: str) -> list[Indicator]:
    text = refang(text)
    found: list[Indicator] = []

    for url in _URL_RE.findall(text):
        url = url.rstrip(".,;:)]}")
        found.append(Indicator("url", url))
        host = urlsplit(url).hostname
        # A URL's host is either an IP (picked up by the IP regex below) or a domain.
        if host and not _is_valid_ip(host):
            found.append(Indicator("domain", host.lower()))

    for ip in _IPV4_RE.findall(text):
        if _is_valid_ip(ip):
            found.append(Indicator("ip", ip))

    for file_hash in _HASH_RE.findall(text):
        found.append(Indicator("hash", file_hash.lower()))

    return found


def extract_indicators(result: dict) -> list[Indicator]:
    """Extract unique indicators from a Splunk result, in the order first seen."""
    strings: list[str] = []
    for key, value in result.items():
        if key.startswith("_") and key not in _SCANNED_INTERNAL_FIELDS:
            continue
        _collect_strings(value, strings)

    unique: dict[Indicator, None] = {}  # a dict keeps insertion order and removes duplicates
    for text in strings:
        for indicator in extract_from_text(text):
            unique.setdefault(indicator, None)
    return list(unique)


def is_enrichable(indicator: Indicator) -> bool:
    """Private and reserved IPs (10.x, 192.168.x, etc.) have no public threat intel."""
    if indicator.type == "ip":
        return ipaddress.ip_address(indicator.value).is_global
    return True
