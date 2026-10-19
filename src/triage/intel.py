"""Threat intel clients for VirusTotal and AbuseIPDB, plus a caching enricher.

Each client takes an optional `session`. In normal use that's a real requests.Session.
In tests it's a fake object that returns saved JSON, so tests never touch the network
and never need API keys. This pattern is called dependency injection.
"""

import base64
import time

import requests

from triage.extract import is_enrichable
from triage.models import Enrichment, Indicator

_HTTP_ERRORS = {
    401: "invalid or missing API key",
    403: "access denied (check API key permissions)",
    429: "rate limit exceeded",
}


class _BaseClient:
    name = "base"

    def __init__(self, session=None, timeout: float = 10.0):
        self.session = session or requests.Session()
        self.timeout = timeout

    def _get(self, indicator: Indicator, url: str, headers: dict, params=None):
        """Send a GET request. Returns (response_json, None) or (None, failed Enrichment)."""
        try:
            response = self.session.get(url, headers=headers, params=params, timeout=self.timeout)
        except requests.RequestException as exc:
            return None, Enrichment(self.name, indicator, "error", error=f"request failed: {exc}")

        if response.status_code == 404:
            return None, Enrichment(self.name, indicator, "not_found")
        if response.status_code != 200:
            message = _HTTP_ERRORS.get(response.status_code, f"HTTP {response.status_code}")
            return None, Enrichment(self.name, indicator, "error", error=message)

        try:
            return response.json(), None
        except ValueError:
            return None, Enrichment(self.name, indicator, "error", error="response was not JSON")


class VirusTotalClient(_BaseClient):
    """VirusTotal API v3. Supports IPs, domains, URLs, and file hashes."""

    name = "virustotal"
    BASE_URL = "https://www.virustotal.com/api/v3"
    _ENDPOINTS = {"ip": "ip_addresses", "domain": "domains", "url": "urls", "hash": "files"}

    def __init__(self, api_key: str, session=None, min_interval: float = 15.0, **kwargs):
        super().__init__(session, **kwargs)
        self.api_key = api_key
        self.min_interval = min_interval
        self._last_request = 0.0

    @staticmethod
    def url_id(url: str) -> str:
        """VirusTotal identifies URLs by their unpadded URL-safe base64 encoding."""
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    def _wait_for_rate_limit(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last_request = time.monotonic()

    def lookup(self, indicator: Indicator) -> Enrichment | None:
        endpoint = self._ENDPOINTS.get(indicator.type)
        if endpoint is None:
            return None
        key = self.url_id(indicator.value) if indicator.type == "url" else indicator.value

        self._wait_for_rate_limit()
        body, failure = self._get(
            indicator, f"{self.BASE_URL}/{endpoint}/{key}", headers={"x-apikey": self.api_key}
        )
        if failure:
            return failure

        attributes = body.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        return Enrichment(
            self.name,
            indicator,
            "ok",
            data={
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attributes.get("reputation"),
            },
        )


class AbuseIPDBClient(_BaseClient):
    """AbuseIPDB API v2. IPs only."""

    name = "abuseipdb"
    CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str, session=None, max_age_days: int = 90, **kwargs):
        super().__init__(session, **kwargs)
        self.api_key = api_key
        self.max_age_days = max_age_days

    def lookup(self, indicator: Indicator) -> Enrichment | None:
        if indicator.type != "ip":
            return None

        body, failure = self._get(
            indicator,
            self.CHECK_URL,
            headers={"Key": self.api_key, "Accept": "application/json"},
            params={"ipAddress": indicator.value, "maxAgeInDays": self.max_age_days},
        )
        if failure:
            return failure

        data = body.get("data", {})
        return Enrichment(
            self.name,
            indicator,
            "ok",
            data={
                "confidence": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "usage_type": data.get("usageType"),
                "is_tor": data.get("isTor"),
                "is_whitelisted": data.get("isWhitelisted"),
            },
        )


class Enricher:
    """Runs every client against every public indicator, caching results.

    The cache matters because the same IP often shows up in many alerts, and the
    free API tiers have tight daily limits.
    """

    def __init__(self, clients: list):
        self.clients = clients
        self._cache: dict[tuple[str, Indicator], Enrichment | None] = {}

    def enrich(self, indicators: list[Indicator]) -> list[Enrichment]:
        results: list[Enrichment] = []
        for indicator in indicators:
            if not is_enrichable(indicator):
                continue
            for client in self.clients:
                key = (client.name, indicator)
                if key not in self._cache:
                    self._cache[key] = client.lookup(indicator)
                if self._cache[key] is not None:
                    results.append(self._cache[key])
        return results
