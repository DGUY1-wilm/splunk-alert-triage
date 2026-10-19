from triage.extract import defang, extract_indicators, is_enrichable, refang
from triage.models import Indicator

SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def test_refang_common_styles():
    assert refang("hxxp://evil[.]com") == "http://evil.com"
    assert refang("HXXPS://evil(.)com") == "https://evil.com"
    assert refang("1.2.3{.}4") == "1.2.3.4"


def test_defang_makes_url_unclickable():
    assert defang("https://evil.com/a") == "hxxps://evil[.]com/a"


def test_extracts_each_indicator_type():
    result = {
        "url": "hxxps://login-micros0ft-verify[.]com/auth",
        "src_ip": "185.220.101.47",
        "file_hash": SHA256,
    }
    found = extract_indicators(result)
    assert Indicator("url", "https://login-micros0ft-verify.com/auth") in found
    assert Indicator("domain", "login-micros0ft-verify.com") in found
    assert Indicator("ip", "185.220.101.47") in found
    assert Indicator("hash", SHA256) in found


def test_sha256_is_not_also_matched_as_md5():
    hashes = [i for i in extract_indicators({"h": SHA256}) if i.type == "hash"]
    assert hashes == [Indicator("hash", SHA256)]


def test_hashes_are_lowercased():
    assert extract_indicators({"h": SHA256.upper()}) == [Indicator("hash", SHA256)]


def test_invalid_ip_is_ignored():
    assert extract_indicators({"x": "version 999.1.1.1"}) == []


def test_duplicates_removed_order_kept():
    result = {"src": "8.8.8.8", "_raw": "conn 8.8.8.8 -> 1.1.1.1"}
    assert extract_indicators(result) == [Indicator("ip", "8.8.8.8"), Indicator("ip", "1.1.1.1")]


def test_nested_and_multivalue_fields_are_scanned():
    result = {"dest": ["8.8.8.8", "1.1.1.1"], "meta": {"peer": "9.9.9.9"}}
    assert len(extract_indicators(result)) == 3


def test_splunk_internal_fields_are_skipped():
    result = {"_bkt": "main~1~" + "a" * 32, "_raw": "seen 8.8.8.8"}
    assert extract_indicators(result) == [Indicator("ip", "8.8.8.8")]


def test_url_with_ip_host_does_not_create_domain():
    found = extract_indicators({"url": "http://185.220.101.47/payload"})
    assert {i.type for i in found} == {"url", "ip"}


def test_private_ips_are_not_enrichable():
    assert not is_enrichable(Indicator("ip", "10.10.30.25"))
    assert not is_enrichable(Indicator("ip", "192.168.1.1"))
    assert is_enrichable(Indicator("ip", "8.8.8.8"))
    assert is_enrichable(Indicator("domain", "example.com"))
