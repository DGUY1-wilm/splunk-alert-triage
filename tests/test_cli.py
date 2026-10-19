import json

from conftest import PROJECT_ROOT

from triage.cli import main

SAMPLES = str(PROJECT_ROOT / "samples" / "alerts")
CONFIG = str(PROJECT_ROOT / "config" / "scoring.yaml")


def test_offline_run_writes_both_reports(tmp_path):
    code = main([SAMPLES, "--offline", "--out", str(tmp_path), "--config", CONFIG])
    assert code == 0
    report = json.loads((tmp_path / "triage_report.json").read_text(encoding="utf-8"))
    assert len(report["results"]) == 5
    assert (tmp_path / "triage_report.md").exists()


def test_offline_run_escalates_privileged_alert(tmp_path):
    main([SAMPLES, "--offline", "--out", str(tmp_path), "--config", CONFIG])
    report = json.loads((tmp_path / "triage_report.json").read_text(encoding="utf-8"))
    by_name = {r["name"]: r["verdict"] for r in report["results"]}
    # Unverified indicator + CORP\administrator -> raised to escalate.
    assert by_name["Brute Force Followed by Successful Login"] == "escalate"


def test_missing_keys_fails_clearly(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.setattr("triage.cli.load_dotenv", lambda: None)  # ignore any local .env
    code = main([SAMPLES, "--out", str(tmp_path), "--config", CONFIG])
    assert code == 2
    assert "VT_API_KEY" in capsys.readouterr().err


def test_missing_input_fails_clearly(tmp_path):
    assert main([str(tmp_path / "nope"), "--offline", "--config", CONFIG]) == 2
