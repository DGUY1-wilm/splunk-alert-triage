"""Turn enrichment results into a triage verdict with human-readable reasons.

The rules, in order:
  1. Any indicator rated high severity                 -> escalate
  2. Otherwise, any indicator rated medium             -> investigate
  3. Otherwise, any public indicator we couldn't check -> investigate
     (fail toward human review: "no data" is not "safe")
  4. No public indicators at all                       -> investigate
  5. Everything checked and clean                      -> likely_benign
  Then: "investigate" on a privileged account or critical host is raised to "escalate".
"""

from pathlib import Path

import yaml

from triage.extract import defang, is_enrichable
from triage.models import Alert, Enrichment, Indicator, Verdict

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


def load_config(path: Path) -> dict:
    with open(path, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _rate(enrichment: Enrichment, config: dict) -> tuple[str, str]:
    """Return (severity, explanation) for one successful lookup."""
    if enrichment.source == "virustotal":
        rules = config["virustotal"]
        count = enrichment.data.get("malicious", 0)
        if count >= rules["high_malicious"]:
            severity = "high"
        elif count >= rules["medium_malicious"]:
            severity = "medium"
        else:
            severity = "low"
        return severity, f"VirusTotal: {count} engines flagged it malicious"

    rules = config["abuseipdb"]
    confidence = enrichment.data.get("confidence", 0)
    if confidence >= rules["high_confidence"]:
        severity = "high"
    elif confidence >= rules["medium_confidence"]:
        severity = "medium"
    else:
        severity = "low"
    return severity, f"AbuseIPDB: abuse confidence {confidence}/100"


def _show(indicator: Indicator) -> str:
    """Defang URLs and domains in reasons so they can't be clicked from a report."""
    return defang(indicator.value) if indicator.type in ("url", "domain") else indicator.value


def _normalize_account(user: str) -> str:
    """CORP\\administrator and administrator@corp.local both become administrator."""
    return user.split("\\")[-1].split("@")[0].lower()


def score_alert(alert: Alert, enrichments: list[Enrichment], config: dict) -> Verdict:
    public = [ind for ind in alert.indicators if is_enrichable(ind)]
    reasons: list[str] = []

    # Highest severity per indicator across all sources; None means no successful lookup.
    best: dict[Indicator, str | None] = {ind: None for ind in public}
    for enrichment in enrichments:
        if enrichment.indicator not in best:
            continue
        if enrichment.status != "ok":
            detail = enrichment.error or "no record found"
            reasons.append(f"{_show(enrichment.indicator)}: {enrichment.source} {detail}")
            continue
        severity, explanation = _rate(enrichment, config)
        reasons.append(f"{_show(enrichment.indicator)}: {explanation} ({severity})")
        current = best[enrichment.indicator]
        if current is None or _SEVERITY_RANK[severity] > _SEVERITY_RANK[current]:
            best[enrichment.indicator] = severity

    severities = set(best.values())
    if not public:
        level = "investigate"
        reasons.append("No public indicators to check; needs manual review.")
    elif "high" in severities:
        level = "escalate"
    elif "medium" in severities:
        level = "investigate"
    elif None in severities:
        level = "investigate"
        unchecked = [_show(ind) for ind, sev in best.items() if sev is None]
        reasons.append(f"Could not verify: {', '.join(unchecked)}. No data is not proof of safe.")
    else:
        level = "likely_benign"

    # Context bump: the same evidence matters more on a domain admin or a domain controller.
    if level == "investigate":
        context = config.get("context", {})
        privileged = {name.lower() for name in context.get("privileged_accounts", [])}
        critical = {name.lower() for name in context.get("critical_hosts", [])}
        if alert.user and _normalize_account(alert.user) in privileged:
            level = "escalate"
            reasons.append(f"Raised to escalate: privileged account '{alert.user}'.")
        elif alert.host and alert.host.lower() in critical:
            level = "escalate"
            reasons.append(f"Raised to escalate: critical host '{alert.host}'.")

    return Verdict(level, reasons)
