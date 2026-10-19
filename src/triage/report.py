"""Write triage results as JSON (for tools) and Markdown (for people)."""

import json
from dataclasses import asdict
from datetime import UTC, datetime

from triage.extract import defang, is_enrichable
from triage.models import TriageResult

# Most urgent first.
_VERDICT_ORDER = {"escalate": 0, "investigate": 1, "likely_benign": 2}
_VERDICT_LABEL = {
    "escalate": "🔴 Escalate",
    "investigate": "🟡 Investigate",
    "likely_benign": "🟢 Likely benign",
}


def sort_results(results: list[TriageResult]) -> list[TriageResult]:
    return sorted(results, key=lambda r: _VERDICT_ORDER[r.verdict.level])


def to_json(results: list[TriageResult]) -> str:
    payload = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "results": [
            {
                "alert_id": r.alert.alert_id,
                "name": r.alert.name,
                "time": r.alert.time,
                "host": r.alert.host,
                "user": r.alert.user,
                "src": r.alert.src,
                "dest": r.alert.dest,
                "verdict": r.verdict.level,
                "reasons": r.verdict.reasons,
                "indicators": [asdict(ind) for ind in r.alert.indicators],
                "enrichments": [asdict(e) for e in r.enrichments],
            }
            for r in sort_results(results)
        ],
    }
    return json.dumps(payload, indent=2)


def _display(value: str, indicator_type: str) -> str:
    # Defang URLs and domains so nobody clicks a live malicious link in the report.
    return defang(value) if indicator_type in ("url", "domain") else value


def _summarize(r: TriageResult, indicator) -> tuple[str, str]:
    """One-cell summaries of the VirusTotal and AbuseIPDB results for an indicator."""
    if not is_enrichable(indicator):
        return "private (skipped)", "private (skipped)"
    cells = {"virustotal": "—", "abuseipdb": "—"}
    for e in r.enrichments:
        if e.indicator != indicator:
            continue
        if e.status != "ok":
            cells[e.source] = e.error or "not found"
        elif e.source == "virustotal":
            cells[e.source] = f"{e.data['malicious']} malicious"
        else:
            cells[e.source] = f"{e.data['confidence']}/100"
    return cells["virustotal"], cells["abuseipdb"]


def to_markdown(results: list[TriageResult]) -> str:
    ordered = sort_results(results)
    counts = {level: 0 for level in _VERDICT_ORDER}
    for r in ordered:
        counts[r.verdict.level] += 1

    lines = [
        "# Alert Triage Report",
        "",
        f"Generated {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')} — {len(ordered)} alerts",
        "",
        "| Verdict | Count |",
        "|---|---|",
    ]
    lines += [f"| {_VERDICT_LABEL[level]} | {counts[level]} |" for level in _VERDICT_ORDER]

    for r in ordered:
        a = r.alert
        lines += [
            "",
            f"## {_VERDICT_LABEL[r.verdict.level]} — {a.name}",
            "",
            f"- **Alert ID:** {a.alert_id}",
            f"- **Time:** {a.time or 'unknown'}",
            f"- **Host:** {a.host or 'unknown'} | **User:** {a.user or 'unknown'}",
            f"- **Source:** {a.src or 'unknown'} | **Destination:** {a.dest or 'unknown'}",
            "",
        ]
        if a.indicators:
            lines += ["| Type | Indicator | VirusTotal | AbuseIPDB |", "|---|---|---|---|"]
            for ind in a.indicators:
                vt, abuse = _summarize(r, ind)
                lines.append(f"| {ind.type} | `{_display(ind.value, ind.type)}` | {vt} | {abuse} |")
            lines.append("")
        lines.append("**Why:**")
        lines += [f"- {reason}" for reason in r.verdict.reasons] or ["- No findings."]

    return "\n".join(lines) + "\n"
