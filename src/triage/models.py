"""Data structures shared by every stage of the pipeline.

Each stage reads and writes these instead of raw dictionaries, so a Splunk field
rename only has to be handled in one place (splunk.py).
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Indicator:
    """One indicator of compromise. Frozen so it can be a dict key (used by the cache)."""

    type: str  # "ip", "domain", "url", or "hash"
    value: str


@dataclass
class Alert:
    """A Splunk alert converted into the tool's common format."""

    alert_id: str
    name: str
    time: str | None
    host: str | None
    user: str | None
    src: str | None
    dest: str | None
    raw: dict
    indicators: list[Indicator] = field(default_factory=list)


@dataclass
class Enrichment:
    """The result of looking up one indicator in one threat intel source."""

    source: str  # "virustotal" or "abuseipdb"
    indicator: Indicator
    status: str  # "ok", "not_found", or "error"
    data: dict = field(default_factory=dict)
    error: str | None = None


@dataclass
class Verdict:
    """The triage decision for an alert, with the reasons that produced it."""

    level: str  # "escalate", "investigate", or "likely_benign"
    reasons: list[str]


@dataclass
class TriageResult:
    alert: Alert
    enrichments: list[Enrichment]
    verdict: Verdict
