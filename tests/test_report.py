import json

from triage.models import Alert, Enrichment, Indicator, TriageResult, Verdict
from triage.report import to_json, to_markdown

URL = Indicator("url", "https://evil.com/login")


def result(level, name="Alert"):
    alert = Alert(name, name, "t", "h", "u", None, None, {}, [URL])
    enrichment = Enrichment("virustotal", URL, "ok", {"malicious": 7})
    return TriageResult(alert, [enrichment], Verdict(level, ["reason one"]))


def test_json_is_valid_and_sorted_most_urgent_first():
    data = json.loads(to_json([result("likely_benign", "B"), result("escalate", "A")]))
    assert [r["verdict"] for r in data["results"]] == ["escalate", "likely_benign"]
    assert data["results"][0]["enrichments"][0]["data"]["malicious"] == 7


def test_markdown_defangs_urls():
    markdown = to_markdown([result("escalate")])
    assert "hxxps://evil[.]com/login" in markdown
    assert "https://evil.com" not in markdown


def test_markdown_shows_counts_and_reasons():
    markdown = to_markdown([result("escalate"), result("investigate")])
    assert "| 🔴 Escalate | 1 |" in markdown
    assert "| 🟢 Likely benign | 0 |" in markdown
    assert "- reason one" in markdown
    assert "7 malicious" in markdown
