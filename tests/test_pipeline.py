"""End to end: load the sample alerts, enrich with mocked APIs, and check every verdict."""

from conftest import PROJECT_ROOT, FakeSession, load_fixture

from triage.intel import AbuseIPDBClient, Enricher, VirusTotalClient
from triage.scoring import score_alert
from triage.splunk import load_alerts

VT = "virustotal.com/api/v3"
ABUSE = "abuseipdb.com/api/v2/check"
EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

# Anything not listed (the phishing URL and domain) returns 404, like a never-seen domain.
ROUTES = {
    f"{VT}/ip_addresses/185.220.101.47": (200, load_fixture("vt_ip_malicious.json")),
    f"{ABUSE}185.220.101.47": (200, load_fixture("abuseipdb_high.json")),
    f"{VT}/ip_addresses/8.8.8.8": (200, load_fixture("vt_ip_clean.json")),
    f"{ABUSE}8.8.8.8": (200, load_fixture("abuseipdb_low.json")),
    f"{VT}/files/{EICAR}": (200, load_fixture("vt_file_malicious.json")),
}

EXPECTED = {
    "Brute Force Followed by Successful Login": "escalate",
    "Suspicious Process Execution from User Downloads": "escalate",
    "Suspicious URL Clicked in Email": "investigate",
    "Outbound Connection to Rare Destination": "likely_benign",
    "Multiple Failed Logins from Internal Host": "investigate",
}


def test_sample_alerts_get_expected_verdicts(config):
    session = FakeSession(ROUTES)
    enricher = Enricher(
        [
            VirusTotalClient("k", session=session, min_interval=0),
            AbuseIPDBClient("k", session=session),
        ]
    )
    verdicts = {}
    for alert in load_alerts(PROJECT_ROOT / "samples" / "alerts"):
        enrichments = enricher.enrich(alert.indicators)
        verdicts[alert.name] = score_alert(alert, enrichments, config).level
    assert verdicts == EXPECTED
