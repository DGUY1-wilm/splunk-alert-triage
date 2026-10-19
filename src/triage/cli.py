"""Command-line entry point.

Examples:
  python -m triage samples/alerts             # full run, needs API keys in .env
  python -m triage samples/alerts --offline   # no API calls, extraction and scoring only
"""

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from triage.intel import AbuseIPDBClient, Enricher, VirusTotalClient
from triage.models import TriageResult
from triage.report import to_json, to_markdown
from triage.scoring import load_config, score_alert
from triage.splunk import load_alerts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="triage", description="Triage Splunk alerts with threat intel enrichment."
    )
    parser.add_argument("input", type=Path, help="Alert JSON file or folder of JSON files")
    parser.add_argument("--out", type=Path, default=Path("reports"), help="Output folder")
    parser.add_argument(
        "--config", type=Path, default=Path("config/scoring.yaml"), help="Scoring rules file"
    )
    parser.add_argument("--offline", action="store_true", help="Skip API lookups (no keys needed)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    load_dotenv()

    if not args.input.exists():
        print(f"error: input not found: {args.input}", file=sys.stderr)
        return 2
    config = load_config(args.config)

    clients = []
    if not args.offline:
        vt_key = os.getenv("VT_API_KEY")
        abuse_key = os.getenv("ABUSEIPDB_API_KEY")
        if not vt_key or not abuse_key:
            print(
                "error: VT_API_KEY and ABUSEIPDB_API_KEY must be set in .env (or use --offline)",
                file=sys.stderr,
            )
            return 2
        clients = [
            VirusTotalClient(vt_key, min_interval=config["virustotal"]["min_interval_seconds"]),
            AbuseIPDBClient(abuse_key),
        ]

    enricher = Enricher(clients)
    alerts = load_alerts(args.input)
    results = []
    for alert in alerts:
        print(f"Triaging {alert.alert_id}: {alert.name} ({len(alert.indicators)} indicators)")
        enrichments = enricher.enrich(alert.indicators)
        results.append(TriageResult(alert, enrichments, score_alert(alert, enrichments, config)))

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "triage_report.json").write_text(to_json(results), encoding="utf-8")
    (args.out / "triage_report.md").write_text(to_markdown(results), encoding="utf-8")

    print()
    for r in results:
        print(f"  {r.verdict.level:<14} {r.alert.name}")
    print(f"\nReports written to {args.out}/")
    return 0
