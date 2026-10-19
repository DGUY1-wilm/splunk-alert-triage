import requests
from conftest import FakeSession, load_fixture

from triage.intel import AbuseIPDBClient, Enricher, VirusTotalClient
from triage.models import Indicator

BAD_IP = Indicator("ip", "185.220.101.47")
GOOD_IP = Indicator("ip", "8.8.8.8")


def vt(routes):
    return VirusTotalClient("test-key", session=FakeSession(routes), min_interval=0)


def test_vt_ip_lookup_parses_stats():
    client = vt({"185.220.101.47": (200, load_fixture("vt_ip_malicious.json"))})
    result = client.lookup(BAD_IP)
    assert result.status == "ok"
    assert result.data["malicious"] == 12
    assert client.session.calls[0]["headers"] == {"x-apikey": "test-key"}


def test_vt_uses_correct_endpoint_per_type():
    client = vt({})
    client.lookup(Indicator("hash", "a" * 64))
    client.lookup(Indicator("domain", "example.com"))
    urls = [call["url"] for call in client.session.calls]
    assert urls[0].endswith("/files/" + "a" * 64)
    assert urls[1].endswith("/domains/example.com")


def test_vt_url_id_is_unpadded_base64():
    assert VirusTotalClient.url_id("http://example.com") == "aHR0cDovL2V4YW1wbGUuY29t"


def test_vt_not_found():
    assert vt({}).lookup(GOOD_IP).status == "not_found"


def test_vt_rate_limited():
    result = vt({"8.8.8.8": (429, None)}).lookup(GOOD_IP)
    assert result.status == "error"
    assert result.error == "rate limit exceeded"


def test_network_failure_is_reported_not_raised():
    class BrokenSession:
        def get(self, *args, **kwargs):
            raise requests.ConnectionError("no network")

    client = VirusTotalClient("k", session=BrokenSession(), min_interval=0)
    result = client.lookup(GOOD_IP)
    assert result.status == "error"
    assert "no network" in result.error


def test_abuseipdb_parses_confidence():
    session = FakeSession({"185.220.101.47": (200, load_fixture("abuseipdb_high.json"))})
    result = AbuseIPDBClient("k", session=session).lookup(BAD_IP)
    assert result.data["confidence"] == 100
    assert result.data["is_tor"] is True
    assert session.calls[0]["params"]["ipAddress"] == "185.220.101.47"


def test_abuseipdb_skips_non_ip_indicators():
    session = FakeSession({})
    assert AbuseIPDBClient("k", session=session).lookup(Indicator("domain", "x.com")) is None
    assert session.calls == []


def test_enricher_caches_repeat_lookups():
    client = vt({"8.8.8.8": (200, load_fixture("vt_ip_clean.json"))})
    enricher = Enricher([client])
    enricher.enrich([GOOD_IP])
    enricher.enrich([GOOD_IP])
    assert len(client.session.calls) == 1


def test_enricher_skips_private_ips():
    client = vt({})
    results = Enricher([client]).enrich([Indicator("ip", "10.0.0.5")])
    assert results == [] and client.session.calls == []
