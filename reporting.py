"""Report generation, Google Drive upload, and webhook alerting for OKGames.ph monitor."""

from __future__ import annotations

import csv
import json
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import MonitorConfig
from .http_client import create_http_session
from .malware import MalwareScanReport
from .uptime import EndpointUptimeResult


PHT_TZ = timezone(timedelta(hours=8))


@dataclass
class DailyMonitorReport:
    timestamp_utc: str
    timestamp_pht: str
    overall_severity: str  # OK | WARNING | CRITICAL
    overall_summary: str
    uptime_results: List[EndpointUptimeResult] = field(default_factory=list)
    malware_report: Optional[MalwareScanReport] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def build_daily_report(
    uptime_results: List[EndpointUptimeResult],
    malware_report: MalwareScanReport,
    now_utc: Optional[datetime] = None,
) -> DailyMonitorReport:
    """Aggregate uptime and malware scan results into a unified daily report."""
    dt_utc = now_utc or datetime.now(timezone.utc)
    dt_pht = dt_utc.astimezone(PHT_TZ)

    severities = [u.severity for u in uptime_results] + [malware_report.severity]
    if "CRITICAL" in severities:
        overall_severity = "CRITICAL"
    elif "WARNING" in severities:
        overall_severity = "WARNING"
    else:
        overall_severity = "OK"

    up_count = sum(1 for u in uptime_results if u.availability_state == "UP")
    waf_count = sum(1 for u in uptime_results if u.availability_state == "WAF_OR_GEOBLOCK")
    down_count = sum(1 for u in uptime_results if u.availability_state == "DOWN")

    summary_parts = [
        f"Endpoints UP: {up_count}/{len(uptime_results)}",
    ]
    if waf_count:
        summary_parts.append(f"WAF/Geo-Challenged: {waf_count}")
    if down_count:
        summary_parts.append(f"DOWN: {down_count}")
    summary_parts.append(f"Malware Scan: {malware_report.overall_status}")

    return DailyMonitorReport(
        timestamp_utc=dt_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
        timestamp_pht=dt_pht.strftime("%Y-%m-%d %I:%M:%S %p PHT"),
        overall_severity=overall_severity,
        overall_summary=" | ".join(summary_parts),
        uptime_results=uptime_results,
        malware_report=malware_report,
    )


def render_markdown_report(report: DailyMonitorReport) -> str:
    """Render a GitHub-Flavored Markdown report suitable for Job Summaries and Drive docs."""
    badge = {
        "OK": "🟢 HEALTHY",
        "WARNING": "🟡 WARNING",
        "CRITICAL": "🔴 CRITICAL ALERT",
    }.get(report.overall_severity, report.overall_severity)

    lines: List[str] = [
        f"# OKGames.ph Daily Security & Uptime Report — {badge}",
        "",
        f"- **Run Time (PHT):** `{report.timestamp_pht}`",
        f"- **Run Time (UTC):** `{report.timestamp_utc}`",
        f"- **Overall Status:** **{badge}** ({report.overall_summary})",
        "",
        "---",
        "",
        "## 1. Downtime, DNS & SSL Availability Summary",
        "",
        "| Endpoint | State | HTTP Status | Latency | Attempts | WAF / Edge | SSL Expiry | DNS IPs |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for up in report.uptime_results:
        state_icon = {
            "UP": "🟢 UP",
            "DEGRADED": "🟡 DEGRADED",
            "WAF_OR_GEOBLOCK": "🟠 WAF / GEO-BLOCK",
            "DOWN": "🔴 DOWN",
        }.get(up.availability_state, up.availability_state)

        http_str = str(up.http_status) if up.http_status is not None else "ERR"
        lat_str = f"{up.response_time_ms:.0f} ms" if up.response_time_ms is not None else "N/A"
        waf_str = up.waf_provider or "None"
        if up.waf_detected:
            waf_str = f"⚠️ {waf_str} Challenge"

        if up.ssl:
            if up.ssl.valid and up.ssl.days_remaining is not None:
                ssl_str = f"✅ {up.ssl.days_remaining}d left"
                if up.ssl.warning:
                    ssl_str = f"⚠️ {up.ssl.days_remaining}d left"
            elif not up.ssl.valid:
                ssl_str = "❌ Invalid/Expired"
            else:
                ssl_str = "N/A"
        else:
            ssl_str = "N/A"

        dns_str = (
            ", ".join(up.dns.ip_addresses[:3])
            if (up.dns and up.dns.resolved)
            else "❌ Failed"
        )

        lines.append(
            f"| `{up.url}` | {state_icon} | `{http_str}` | `{lat_str}` | "
            f"`{up.attempts_used}` | {waf_str} | {ssl_str} | `{dns_str}` |"
        )

    # Detailed uptime issues / redirect chains
    for up in report.uptime_results:
        if up.issues or len(up.redirect_chain) > 1:
            lines.extend(["", f"### Details for `{up.url}`"])
            if len(up.redirect_chain) > 1:
                chain_str = " -> ".join(f"`{c}`" for c in up.redirect_chain)
                lines.append(f"- **Redirect Chain:** {chain_str}")
            for issue in up.issues:
                lines.append(f"- ⚠️ {issue}")

    lines.extend([
        "",
        "---",
        "",
        "## 2. Layered Malware & Threat Intelligence Scan",
        "",
    ])

    mw = report.malware_report
    if mw:
        mw_badge = {
            "CLEAN": "🟢 CLEAN",
            "SUSPICIOUS": "🟡 SUSPICIOUS",
            "INFECTED": "🔴 INFECTED / FLAGGED",
        }.get(mw.overall_status, mw.overall_status)
        lines.append(f"**Overall Malware Status:** {mw_badge}")
        lines.append("")

        # Reputation table
        lines.extend([
            "### Threat Intelligence & Public Blocklists",
            "",
            "| Intelligence Source | Status | Details |",
            "| :--- | :--- | :--- |",
        ])
        for rep in mw.reputation_checks:
            rep_icon = {
                "CLEAN": "✅ CLEAN",
                "FLAGGED": "🔴 FLAGGED",
                "SKIPPED": "⚪ SKIPPED",
                "ERROR": "⚠️ ERROR",
            }.get(rep.status, rep.status)
            lines.append(f"| **{rep.source}** | {rep_icon} | {rep.detail} |")

        # Playwright deep scan table
        if mw.playwright_results:
            lines.extend([
                "",
                "### Headless Browser (Playwright) Runtime Inspection",
                "",
                "| URL | Executed | Final URL | External Domains | Unrecognized Domains | Console Errors |",
                "| :--- | :--- | :--- | :--- | :--- | :--- |",
            ])
            for pw in mw.playwright_results:
                exec_str = "✅ Yes" if pw.executed else f"⚠️ No ({pw.error or 'skipped'})"
                final_u = f"`{pw.final_url}`" if pw.final_url else "N/A"
                ext_cnt = str(len(pw.external_domains_contacted))
                unk_cnt = (
                    f"⚠️ {len(pw.unknown_third_party_domains)} ({', '.join(pw.unknown_third_party_domains[:5])})"
                    if pw.unknown_third_party_domains
                    else "✅ 0"
                )
                err_cnt = str(len(pw.console_errors))
                lines.append(
                    f"| `{pw.url}` | {exec_str} | {final_u} | {ext_cnt} | {unk_cnt} | {err_cnt} |"
                )

        # Findings list
        lines.extend(["", "### Heuristic & Runtime Security Findings", ""])
        if not mw.findings:
            lines.append("- ✅ No malware signatures, hidden iframes, or unauthorized script injections detected.")
        else:
            for f in mw.findings:
                f_icon = "🔴" if f.severity == "CRITICAL" else "🟡"
                lines.append(f"- {f_icon} **[{f.layer} / {f.severity}] {f.title}** — {f.detail}")

        # Missing security headers
        if any(mw.missing_security_headers.values()):
            lines.extend(["", "### HTTP Security Header Recommendations", ""])
            for u, missing in mw.missing_security_headers.items():
                if missing:
                    lines.append(f"- `{u}` is missing recommended headers: `{', '.join(missing)}`")

    lines.append("")
    return "\n".join(lines)


def write_report_files(
    report: DailyMonitorReport,
    output_dir: Path,
    date_slug: Optional[str] = None,
) -> Dict[str, Path]:
    """Write Markdown, JSON, and cumulative CSV history files to output_dir."""
    output_dir.mkdir(parents=True, exist_ok=True)
    slug = date_slug or datetime.now(PHT_TZ).strftime("%Y-%m-%d")

    md_content = render_markdown_report(report)
    json_content = json.dumps(report.to_dict(), indent=2)

    dated_md = output_dir / f"okgames-report-{slug}.md"
    latest_md = output_dir / "latest-report.md"
    dated_json = output_dir / f"okgames-report-{slug}.json"
    latest_json = output_dir / "latest-report.json"
    history_csv = output_dir / "okgames-history.csv"

    dated_md.write_text(md_content, encoding="utf-8")
    latest_md.write_text(md_content, encoding="utf-8")
    dated_json.write_text(json_content, encoding="utf-8")
    latest_json.write_text(json_content, encoding="utf-8")

    # Append to cumulative CSV log
    csv_exists = history_csv.exists()
    with history_csv.open("a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not csv_exists:
            writer.writerow([
                "timestamp_pht",
                "timestamp_utc",
                "overall_severity",
                "url",
                "availability_state",
                "http_status",
                "response_time_ms",
                "waf_detected",
                "ssl_days_remaining",
                "malware_status",
                "malware_findings_count",
            ])
        mw_status = report.malware_report.overall_status if report.malware_report else "UNKNOWN"
        mw_count = len(report.malware_report.findings) if report.malware_report else 0
        for up in report.uptime_results:
            writer.writerow([
                report.timestamp_pht,
                report.timestamp_utc,
                report.overall_severity,
                up.url,
                up.availability_state,
                up.http_status if up.http_status is not None else "",
                up.response_time_ms if up.response_time_ms is not None else "",
                up.waf_detected,
                up.ssl.days_remaining if (up.ssl and up.ssl.days_remaining is not None) else "",
                mw_status,
                mw_count,
            ])

    return {
        "dated_md": dated_md,
        "latest_md": latest_md,
        "dated_json": dated_json,
        "latest_json": latest_json,
        "history_csv": history_csv,
    }


def upload_to_gdrive(
    files_to_upload: List[Path],
    config: MonitorConfig,
) -> List[str]:
    """Upload report files to the OKGames Google Drive folder.

    Supports:
    1. Service Account JSON via GDRIVE_SERVICE_ACCOUNT_JSON (for GitHub Actions)
    2. Local `gdrive` CLI if installed and authenticated in the environment
    """
    uploaded: List[str] = []
    folder_id = config.gdrive_folder_id
    if not folder_id:
        return uploaded

    # Method 1: Google Drive API with Service Account JSON (GitHub Actions)
    if config.gdrive_service_account_json:
        try:
            from google.oauth2 import service_account
            from googleapiclient.discovery import build
            from googleapiclient.http import MediaFileUpload

            creds_info = json.loads(config.gdrive_service_account_json)
            creds = service_account.Credentials.from_service_account_info(
                creds_info,
                scopes=["https://www.googleapis.com/auth/drive.file"],
            )
            service = build("drive", "v3", credentials=creds)

            for file_path in files_to_upload:
                if not file_path.exists():
                    continue
                media = MediaFileUpload(str(file_path), resumable=False)
                metadata = {"name": file_path.name, "parents": [folder_id]}
                created = (
                    service.files()
                    .create(body=metadata, media_body=media, fields="id,name")
                    .execute()
                )
                uploaded.append(f"{created.get('name')} (id={created.get('id')})")
            return uploaded
        except Exception as exc:
            print(f"[WARN] Service account Google Drive upload failed: {exc}")

    # Method 2: `gdrive` CLI fallback (if present on PATH)
    gdrive_bin = shutil.which("gdrive")
    if gdrive_bin:
        for file_path in files_to_upload:
            if not file_path.exists():
                continue
            try:
                proc = subprocess.run(
                    [gdrive_bin, "mutate", "upload", str(file_path), "--parent", folder_id],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                if proc.returncode == 0:
                    uploaded.append(file_path.name)
                else:
                    print(f"[WARN] gdrive CLI upload returned {proc.returncode}: {proc.stderr.strip()}")
            except Exception as exc:
                print(f"[WARN] gdrive CLI upload failed for {file_path.name}: {exc}")

    return uploaded


def send_webhook_alerts(
    report: DailyMonitorReport,
    config: MonitorConfig,
    session: Optional[Any] = None,
) -> List[str]:
    """Dispatch notifications to Slack, Discord, and/or Telegram webhooks if configured."""
    sent_channels: List[str] = []
    sess = session or create_http_session()

    badge = {
        "OK": "🟢 HEALTHY",
        "WARNING": "🟡 WARNING",
        "CRITICAL": "🔴 CRITICAL ALERT",
    }.get(report.overall_severity, report.overall_severity)

    issues_summary: List[str] = []
    for up in report.uptime_results:
        for iss in up.issues:
            issues_summary.append(f"• [{up.url}] {iss}")
    if report.malware_report:
        for f in report.malware_report.findings:
            issues_summary.append(f"• [{f.layer}/{f.severity}] {f.title}: {f.detail}")

    details_block = "\n".join(issues_summary[:10]) if issues_summary else "All checks passed."
    text_message = (
        f"*{badge} — OKGames.ph Daily Monitor*\n"
        f"Time: {report.timestamp_pht}\n"
        f"Summary: {report.overall_summary}\n\n"
        f"{details_block}"
    )

    if config.slack_webhook_url:
        try:
            resp = sess.post(
                config.slack_webhook_url,
                json={"text": text_message},
                timeout=10.0,
            )
            if resp.ok:
                sent_channels.append("Slack")
        except Exception as exc:
            print(f"[WARN] Failed to send Slack webhook: {exc}")

    if config.discord_webhook_url:
        try:
            resp = sess.post(
                config.discord_webhook_url,
                json={"content": text_message[:1950]},
                timeout=10.0,
            )
            if resp.ok:
                sent_channels.append("Discord")
        except Exception as exc:
            print(f"[WARN] Failed to send Discord webhook: {exc}")

    if config.telegram_bot_token and config.telegram_chat_id:
        try:
            tg_url = f"https://api.telegram.org/bot{config.telegram_bot_token}/sendMessage"
            resp = sess.post(
                tg_url,
                json={
                    "chat_id": config.telegram_chat_id,
                    "text": text_message,
                },
                timeout=10.0,
            )
            if resp.ok:
                sent_channels.append("Telegram")
        except Exception as exc:
            print(f"[WARN] Failed to send Telegram alert: {exc}")

    return sent_channels
