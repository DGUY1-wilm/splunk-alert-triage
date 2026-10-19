from triage.models import Alert, Enrichment, Indicator
from triage.scoring import score_alert

IP = Indicator("ip", "185.220.101.47")


def make_alert(indicators, user="jdoe", host="WKS-001"):
    return Alert("id", "Test", None, host, user, None, None, {}, indicators)


def vt(indicator, malicious, status="ok"):
    return Enrichment("virustotal", indicator, status, {"malicious": malicious})


def abuse(indicator, confidence):
    return Enrichment("abuseipdb", indicator, "ok", {"confidence": confidence})


def test_high_severity_escalates(config):
    verdict = score_alert(make_alert([IP]), [abuse(IP, 100)], config)
    assert verdict.level == "escalate"
    assert any("100/100" in reason for reason in verdict.reasons)


def test_medium_severity_investigates(config):
    assert score_alert(make_alert([IP]), [vt(IP, 2)], config).level == "investigate"


def test_all_clean_is_likely_benign(config):
    verdict = score_alert(make_alert([IP]), [vt(IP, 0), abuse(IP, 0)], config)
    assert verdict.level == "likely_benign"


def test_worst_source_wins(config):
    # VirusTotal says clean, AbuseIPDB says high: the high rating must count.
    assert score_alert(make_alert([IP]), [vt(IP, 0), abuse(IP, 90)], config).level == "escalate"


def test_unverified_indicator_needs_review(config):
    lookup_failed = Enrichment("virustotal", IP, "not_found")
    verdict = score_alert(make_alert([IP]), [lookup_failed], config)
    assert verdict.level == "investigate"
    assert any("Could not verify" in reason for reason in verdict.reasons)


def test_one_clean_one_unchecked_is_not_benign(config):
    domain = Indicator("domain", "new-domain.com")
    alert = make_alert([IP, domain])
    assert score_alert(alert, [vt(IP, 0)], config).level == "investigate"


def test_no_public_indicators_needs_review(config):
    verdict = score_alert(make_alert([Indicator("ip", "10.0.0.5")]), [], config)
    assert verdict.level == "investigate"


def test_privileged_account_bumps_to_escalate(config):
    alert = make_alert([IP], user="CORP\\Administrator")
    verdict = score_alert(alert, [vt(IP, 2)], config)
    assert verdict.level == "escalate"
    assert any("privileged account" in reason for reason in verdict.reasons)


def test_upn_style_account_is_normalized(config):
    alert = make_alert([IP], user="admin@corp.local")
    assert score_alert(alert, [vt(IP, 2)], config).level == "escalate"


def test_critical_host_bumps_to_escalate(config):
    alert = make_alert([IP], host="dc01")
    assert score_alert(alert, [vt(IP, 2)], config).level == "escalate"


def test_context_does_not_bump_benign(config):
    alert = make_alert([IP], user="administrator")
    assert score_alert(alert, [vt(IP, 0), abuse(IP, 0)], config).level == "likely_benign"


def test_thresholds_come_from_config(config):
    config["abuseipdb"]["high_confidence"] = 101  # make "high" unreachable
    assert score_alert(make_alert([IP]), [abuse(IP, 100)], config).level == "investigate"
