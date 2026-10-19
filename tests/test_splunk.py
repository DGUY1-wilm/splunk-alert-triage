import json

from conftest import PROJECT_ROOT

from triage.splunk import load_alerts, parse_payload

SAMPLES = PROJECT_ROOT / "samples" / "alerts"


def test_webhook_payload_maps_fields():
    alert = parse_payload(
        "x",
        {
            "search_name": "Test Alert",
            "sid": "sid123",
            "result": {"_time": "t", "dest_host": "DC01", "user": "bob", "src_ip": "8.8.8.8"},
        },
    )
    assert alert.alert_id == "sid123"
    assert alert.name == "Test Alert"
    assert (alert.host, alert.user, alert.src) == ("DC01", "bob", "8.8.8.8")


def test_bare_result_without_wrapper():
    alert = parse_payload("file1", {"src": "8.8.8.8"})
    assert alert.alert_id == "file1"
    assert alert.name == "Unnamed alert"
    assert alert.src == "8.8.8.8"


def test_multivalue_field_uses_first_entry():
    alert = parse_payload("x", {"result": {"user": ["alice", "bob"]}})
    assert alert.user == "alice"


def test_missing_fields_are_none():
    alert = parse_payload("x", {"result": {}})
    assert alert.host is None and alert.user is None and alert.indicators == []


def test_ndjson_export_format(tmp_path):
    lines = [
        {"preview": False, "result": {"src_ip": "8.8.8.8"}},
        {"preview": False, "result": {"src_ip": "1.1.1.1"}},
    ]
    file = tmp_path / "export.json"
    file.write_text("\n".join(json.dumps(line) for line in lines), encoding="utf-8")
    alerts = load_alerts(file)
    assert [a.alert_id for a in alerts] == ["export-1", "export-2"]


def test_json_list_format(tmp_path):
    file = tmp_path / "many.json"
    file.write_text(json.dumps([{"result": {}}, {"result": {}}]), encoding="utf-8")
    assert len(load_alerts(file)) == 2


def test_loads_all_sample_alerts():
    alerts = load_alerts(SAMPLES)
    assert len(alerts) == 5
    assert all(a.name != "Unnamed alert" for a in alerts)
