"""CLI entrypoint for the OKGames.ph Daily Malware & Downtime Monitor."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import List, Optional

from .config import MonitorConfig
from .malware import run_malware_scan
from .reporting import (
    build_daily_report,
    render_markdown_report,
    send_webhook_alerts,
    upload_to_gdrive,
    write_report_files,
)
from .uptime import check_endpoint_uptime


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run daily downtime and layered malware checks for OKGames.ph."
    )
    parser.add_argument(
        "--urls",
        nargs="*",
        help="Override target URLs to check (default: https://okgames.ph https://www.okgames.ph).",
    )
    parser.add_argument(
        "--output-dir",
        default="./reports",
        help="Directory to write Markdown, JSON, CSV, and screenshot artifacts (default: ./reports).",
    )
    parser.add_argument(
        "--skip-playwright",
        action="store_true",
        help="Skip Playwright headless browser scan (run HTTP + heuristic + API checks only).",
    )
    parser.add_argument(
        "--upload-gdrive",
        action="store_true",
        help="Upload generated daily report files to the configured OKGames Google Drive folder.",
    )
    parser.add_argument(
        "--notify-always",
        action="store_true",
        help="Send webhook notifications even when status is OK (default: only on WARNING or CRITICAL).",
    )
    parser.add_argument(
        "--fail-on-warning",
        action="store_true",
        help="Exit with non-zero code on WARNING as well as CRITICAL.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    config = MonitorConfig.from_env(target_urls=args.urls if args.urls else None)
    if args.skip_playwright:
        config.enable_playwright = False

    output_dir = Path(args.output_dir).resolve()

    print(f"[*] Starting OKGames.ph Daily Monitor for targets: {', '.join(config.target_urls)}")
    uptime_results = []
    for url in config.target_urls:
        print(f"    -> Checking availability, DNS, SSL, and WAF state for {url} ...")
        up_res = check_endpoint_uptime(url, config)
        uptime_results.append(up_res)
        print(
            f"       State={up_res.availability_state} | HTTP={up_res.http_status} | "
            f"Latency={up_res.response_time_ms}ms | Severity={up_res.severity}"
        )

    print("[*] Running layered malware & threat intelligence scan ...")
    malware_report = run_malware_scan(
        uptime_results=uptime_results,
        config=config,
        output_dir=output_dir,
    )
    print(
        f"    -> Malware Status={malware_report.overall_status} | "
        f"Findings={len(malware_report.findings)} | Severity={malware_report.severity}"
    )

    daily_report = build_daily_report(
        uptime_results=uptime_results,
        malware_report=malware_report,
    )
    paths = write_report_files(daily_report, output_dir=output_dir)
    print(f"[*] Wrote reports to {output_dir}:")
    for k, p in paths.items():
        print(f"    - {k}: {p}")

    # Write to GitHub Actions Step Summary if running inside GitHub Actions
    step_summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary_path:
        try:
            with open(step_summary_path, "a", encoding="utf-8") as sf:
                sf.write(render_markdown_report(daily_report) + "\n")
            print("[*] Published Markdown report to GITHUB_STEP_SUMMARY.")
        except Exception as exc:
            print(f"[WARN] Could not write to GITHUB_STEP_SUMMARY: {exc}")

    # Upload to Google Drive if requested or if GDRIVE_SERVICE_ACCOUNT_JSON is set
    if args.upload_gdrive or config.gdrive_service_account_json:
        uploaded = upload_to_gdrive(
            [paths["dated_md"], paths["dated_json"], paths["history_csv"]],
            config=config,
        )
        if uploaded:
            print(f"[*] Uploaded to OKGames Google Drive folder ({config.gdrive_folder_id}): {', '.join(uploaded)}")

    # Send Webhook alerts on non-OK status (or when --notify-always is set)
    if daily_report.overall_severity in ("CRITICAL", "WARNING") or args.notify_always:
        sent = send_webhook_alerts(daily_report, config=config)
        if sent:
            print(f"[*] Sent alerts to: {', '.join(sent)}")

    if daily_report.overall_severity == "CRITICAL":
        return 1
    if daily_report.overall_severity == "WARNING" and args.fail_on_warning:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
