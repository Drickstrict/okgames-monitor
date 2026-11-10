"""Configuration and data models for OKGames.ph monitoring."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional


DEFAULT_TARGET_URLS = [
    "https://okgames.ph",
    "https://www.okgames.ph",
]

# Known benign third-party script/resource domains commonly used by web platforms.
DEFAULT_ALLOWED_THIRD_PARTY_DOMAINS = [
    "okgames.ph",
    "okbet.com",
    "googleapis.com",
    "gstatic.com",
    "googletagmanager.com",
    "google-analytics.com",
    "google.com",
    "cloudflare.com",
    "cloudflareinsights.com",
    "jsdelivr.net",
    "cdnjs.cloudflare.com",
    "unpkg.com",
    "facebook.net",
    "facebook.com",
    "doubleclick.net",
    "tiktok.com",
    "byteoversea.com",
    "adjust.com",
    "appsflyer.com",
    "intercom.io",
    "intercomcdn.com",
    "zendesk.com",
    "zdassets.com",
    "livechatinc.com",
    "onesignal.com",
    "sentry.io",
]


@dataclass
class MonitorConfig:
    """Runtime configuration for the daily downtime and malware check."""

    target_urls: List[str] = field(default_factory=lambda: list(DEFAULT_TARGET_URLS))
    latency_warning_seconds: float = 5.0
    ssl_expiry_warning_days: int = 14
    max_retries: int = 3
    retry_delay_seconds: float = 10.0
    timeout_seconds: float = 20.0
    enable_playwright: bool = True
    allowed_third_party_domains: List[str] = field(
        default_factory=lambda: list(DEFAULT_ALLOWED_THIRD_PARTY_DOMAINS)
    )
    expected_keywords: List[str] = field(default_factory=lambda: ["okgames"])

    # Optional proxy for geo-restricted or WAF-protected checks
    proxy_url: Optional[str] = None

    # Threat intelligence API keys (optional; loaded from environment / GitHub Secrets)
    virustotal_api_key: Optional[str] = None
    google_safe_browsing_api_key: Optional[str] = None
    urlhaus_auth_key: Optional[str] = None

    # Reporting & Alerting
    gdrive_folder_id: str = "1quiLsHcrWb4JtKEGACsc4KVWBEGC0Nm9"
    gdrive_service_account_json: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    discord_webhook_url: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None

    @classmethod
    def from_env(cls, target_urls: Optional[List[str]] = None) -> "MonitorConfig":
        """Build a MonitorConfig populated from environment variables."""
        env_urls = os.environ.get("MONITOR_TARGET_URLS", "").strip()
        resolved_urls = (
            target_urls
            if target_urls
            else ([u.strip() for u in env_urls.split(",") if u.strip()] or list(DEFAULT_TARGET_URLS))
        )

        # Support explicit MONITOR_PROXY_URL so users can configure a dedicated PH proxy
        # in GitHub Secrets without interfering with runner setup steps.
        proxy_url = os.environ.get("MONITOR_PROXY_URL") or None

        extra_allowed = os.environ.get("MONITOR_ALLOWED_DOMAINS", "").strip()
        allowed_domains = list(DEFAULT_ALLOWED_THIRD_PARTY_DOMAINS)
        if extra_allowed:
            allowed_domains.extend([d.strip().lower() for d in extra_allowed.split(",") if d.strip()])

        return cls(
            target_urls=resolved_urls,
            latency_warning_seconds=float(os.environ.get("MONITOR_LATENCY_WARN_SEC", "5.0")),
            ssl_expiry_warning_days=int(os.environ.get("MONITOR_SSL_WARN_DAYS", "14")),
            max_retries=int(os.environ.get("MONITOR_MAX_RETRIES", "3")),
            retry_delay_seconds=float(os.environ.get("MONITOR_RETRY_DELAY_SEC", "10.0")),
            timeout_seconds=float(os.environ.get("MONITOR_TIMEOUT_SEC", "20.0")),
            enable_playwright=os.environ.get("MONITOR_ENABLE_PLAYWRIGHT", "true").lower()
            not in ("0", "false", "no"),
            allowed_third_party_domains=allowed_domains,
            proxy_url=proxy_url,
            virustotal_api_key=os.environ.get("VIRUSTOTAL_API_KEY") or None,
            google_safe_browsing_api_key=os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY") or None,
            urlhaus_auth_key=os.environ.get("URLHAUS_AUTH_KEY") or None,
            gdrive_folder_id=os.environ.get(
                "GDRIVE_FOLDER_ID", "1quiLsHcrWb4JtKEGACsc4KVWBEGC0Nm9"
            ),
            gdrive_service_account_json=os.environ.get("GDRIVE_SERVICE_ACCOUNT_JSON") or None,
            slack_webhook_url=os.environ.get("SLACK_WEBHOOK_URL") or None,
            discord_webhook_url=os.environ.get("DISCORD_WEBHOOK_URL") or None,
            telegram_bot_token=os.environ.get("TELEGRAM_BOT_TOKEN") or None,
            telegram_chat_id=os.environ.get("TELEGRAM_CHAT_ID") or None,
        )

    def requests_proxies(self) -> Optional[Dict[str, str]]:
        """Return a requests-compatible proxies dict if proxy_url is configured."""
        if not self.proxy_url:
            return None
        return {
            "http": self.proxy_url,
            "https": self.proxy_url,
        }
