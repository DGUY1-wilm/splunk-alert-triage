"""Shared test helpers.

FakeSession stands in for requests.Session. It returns saved JSON from tests/fixtures
based on the requested URL, so no test touches the network or needs API keys.
"""

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
PROJECT_ROOT = Path(__file__).parent.parent


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class FakeResponse:
    def __init__(self, status_code: int, body=None):
        self.status_code = status_code
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no JSON body")
        return self._body


class FakeSession:
    """Maps a URL substring to a (status_code, body) response and records every call."""

    def __init__(self, routes: dict[str, tuple[int, dict | None]]):
        self.routes = routes
        self.calls: list[dict] = []

    def get(self, url, headers=None, params=None, timeout=None):
        self.calls.append({"url": url, "headers": headers, "params": params})
        # AbuseIPDB puts the IP in the query string, not the URL path.
        target = url + (params or {}).get("ipAddress", "")
        for fragment, (status, body) in self.routes.items():
            if fragment in target:
                return FakeResponse(status, body)
        return FakeResponse(404)


@pytest.fixture
def config():
    from triage.scoring import load_config

    return load_config(PROJECT_ROOT / "config" / "scoring.yaml")
