"""Downtime, DNS, SSL/TLS, and WAF/Geo-Restriction checks for OKGames.ph."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from .config import MonitorConfig
from .http_client import create_http_session


WAF_BODY_SIGNATURES = [
    "attention required! | cloudflare",
    "just a moment...",
    "cf-browser-verification",
    "__cf_chl_opt",
    "challenge-platform",
    "access denied",
    "sucuri website firewall",
    "akamaiighost",
    "geo-restricted",
    "not available in your country",
    "not available in your region",
    "blocked in your country",
]

CLOUDFLARE_ORIGIN_DOWN_CODES = {520, 521, 522, 523, 524, 525, 526, 530}


@dataclass
class DNSCheckResult:
    hostname: str
    resolved: bool
    ip_addresses: List[str] = field(default_factory=list)
    lookup_time_ms: float = 0.0
    has_bogon_ip: bool = False
    error: Optional[str] = None


@dataclass
class SSLCheckResult:
    hostname: str
    valid: bool
    issuer: Optional[str] = None
    subject: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    days_remaining: Optional[int] = None
    warning: Optional[str] = None
    error: Optional[str] = None


@dataclass
class EndpointUptimeResult:
    url: str
    final_url: Optional[str] = None
    availability_state: str = "DOWN"  # UP | DEGRADED | WAF_OR_GEOBLOCK | DOWN
    severity: str = "CRITICAL"  # OK | WARNING | CRITICAL
    http_status: Optional[int] = None
    response_time_ms: Optional[float] = None
    attempts_used: int = 0
    redirect_chain: List[str] = field(default_factory=list)
    waf_detected: bool = False
    waf_provider: Optional[str] = None
    waf_detail: Optional[str] = None
    dns: Optional[DNSCheckResult] = None
    ssl: Optional[SSLCheckResult] = None
    html_snippet: str = ""
    response_headers: Dict[str, str] = field(default_factory=dict)
    issues: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def check_dns(hostname: str) -> DNSCheckResult:
    """Resolve A/AAAA records for hostname and check for bogon/hijacked IPs."""
    start = time.monotonic()
    try:
        infos = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
        elapsed_ms = round((time.monotonic() - start) * 1000.0, 2)
        ips = sorted({info[4][0] for info in infos if info and info[4]})
        has_bogon = False
        for ip_str in ips:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                    has_bogon = True
            except ValueError:
                pass
        return DNSCheckResult(
            hostname=hostname,
            resolved=len(ips) > 0,
            ip_addresses=ips,
            lookup_time_ms=elapsed_ms,
            has_bogon_ip=has_bogon,
        )
    except Exception as exc:
        elapsed_ms = round((time.monotonic() - start) * 1000.0, 2)
        return DNSCheckResult(
            hostname=hostname,
            resolved=False,
            lookup_time_ms=elapsed_ms,
            error=str(exc),
        )


def check_ssl_certificate(
    hostname: str,
    port: int = 443,
    timeout: float = 10.0,
    warn_days: int = 14,
) -> SSLCheckResult:
    """Verify TLS handshake and certificate expiration window."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return SSLCheckResult(
                        hostname=hostname,
                        valid=False,
                        error="Peer did not return a certificate.",
                    )

                not_after_str = cert.get("notAfter")
                not_before_str = cert.get("notBefore")
                issuer_parts = [
                    f"{k}={v}"
                    for rdn in cert.get("issuer", ())
                    for k, v in rdn
                ]
                subject_parts = [
                    f"{k}={v}"
                    for rdn in cert.get("subject", ())
                    for k, v in rdn
                ]

                days_remaining: Optional[int] = None
                warning: Optional[str] = None
                if not_after_str:
                    expiry_dt = datetime.strptime(
                        not_after_str, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    now_dt = datetime.now(timezone.utc)
                    days_remaining = int((expiry_dt - now_dt).total_seconds() // 86400)
                    if days_remaining < 0:
                        return SSLCheckResult(
                            hostname=hostname,
                            valid=False,
                            issuer=", ".join(issuer_parts),
                            subject=", ".join(subject_parts),
                            not_before=not_before_str,
                            not_after=not_after_str,
                            days_remaining=days_remaining,
                            error=f"SSL certificate expired {-days_remaining} days ago ({not_after_str}).",
                        )
                    if days_remaining < warn_days:
                        warning = (
                            f"SSL certificate expires in {days_remaining} days "
                            f"(threshold: {warn_days} days; expires {not_after_str})."
                        )

                return SSLCheckResult(
                    hostname=hostname,
                    valid=True,
                    issuer=", ".join(issuer_parts),
                    subject=", ".join(subject_parts),
                    not_before=not_before_str,
                    not_after=not_after_str,
                    days_remaining=days_remaining,
                    warning=warning,
                )
    except Exception as exc:
        return SSLCheckResult(
            hostname=hostname,
            valid=False,
            error=str(exc),
        )


def classify_waf_or_geoblock(
    status_code: int,
    headers: Dict[str, str],
    body_text: str,
) -> tuple[bool, Optional[str], Optional[str]]:
    """Detect whether an HTTP response is a WAF challenge or geo-restriction page."""
    lower_headers = {k.lower(): v for k, v in headers.items()}
    server_hdr = lower_headers.get("server", "").lower()
    body_lower = (body_text or "")[:15000].lower()

    provider: Optional[str] = None
    if "cloudflare" in server_hdr or "cf-ray" in lower_headers:
        provider = "Cloudflare"
    elif "sucuri" in server_hdr or "x-sucuri-id" in lower_headers:
        provider = "Sucuri"
    elif "akamai" in server_hdr or any(k.startswith("x-akamai") for k in lower_headers):
        provider = "Akamai"
    elif "imperva" in server_hdr or "x-iinfo" in lower_headers:
        provider = "Imperva/Incapsula"

    # Explicit Cloudflare mitigated header
    if lower_headers.get("cf-mitigated", "").lower() == "challenge":
        return (
            True,
            provider or "Cloudflare",
            f"HTTP {status_code} with cf-mitigated=challenge header (bot/WAF challenge).",
        )

    if status_code in (401, 403, 429, 503):
        for sig in WAF_BODY_SIGNATURES:
            if sig in body_lower:
                return (
                    True,
                    provider or "WAF/Geo-Filter",
                    f"HTTP {status_code} matched WAF/geo-restriction signature '{sig}'.",
                )
        if provider and status_code == 403:
            return (
                True,
                provider,
                f"HTTP 403 Forbidden returned by {provider} edge (likely datacenter IP or geo-restriction block).",
            )

    return False, provider, None


def check_endpoint_uptime(
    url: str,
    config: MonitorConfig,
    session: Optional[Any] = None,
) -> EndpointUptimeResult:
    """Run DNS, SSL, and HTTP availability checks (with retries) for a single URL."""
    parsed = urlparse(url)
    hostname = parsed.hostname or url
    result = EndpointUptimeResult(url=url)

    # 1. DNS Check
    dns_res = check_dns(hostname)
    result.dns = dns_res
    if not dns_res.resolved:
        result.issues.append(f"DNS resolution failed for {hostname}: {dns_res.error}")
    elif dns_res.has_bogon_ip:
        result.issues.append(
            f"Suspicious private/reserved bogon IP returned for {hostname}: {dns_res.ip_addresses}"
        )

    # 2. SSL Certificate Check (if HTTPS)
    if parsed.scheme.lower() == "https" and dns_res.resolved:
        ssl_res = check_ssl_certificate(
            hostname=hostname,
            timeout=min(config.timeout_seconds, 10.0),
            warn_days=config.ssl_expiry_warning_days,
        )
        result.ssl = ssl_res
        if not ssl_res.valid:
            result.issues.append(f"SSL certificate check failed: {ssl_res.error}")
        elif ssl_res.warning:
            result.issues.append(ssl_res.warning)

    # 3. HTTP Check with retries
    sess = session or create_http_session()
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36 OKGamesMonitor/1.0"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-PH,en-US;q=0.9,en;q=0.8",
    }

    last_error: Optional[str] = None
    last_response: Optional[Any] = None
    last_elapsed_ms: Optional[float] = None

    for attempt in range(1, max(1, config.max_retries) + 1):
        result.attempts_used = attempt
        start = time.monotonic()
        try:
            resp = sess.get(
                url,
                headers=headers,
                timeout=config.timeout_seconds,
                allow_redirects=True,
                proxies=config.requests_proxies(),
            )
            elapsed_ms = round((time.monotonic() - start) * 1000.0, 2)
            last_response = resp
            last_elapsed_ms = elapsed_ms
            last_error = None

            # Retry on 5xx server errors, otherwise break immediately
            if resp.status_code < 500:
                break
            last_error = f"HTTP {resp.status_code} Server Error"
        except Exception as exc:
            last_elapsed_ms = round((time.monotonic() - start) * 1000.0, 2)
            last_error = str(exc)

        if attempt < config.max_retries and config.retry_delay_seconds > 0:
            time.sleep(config.retry_delay_seconds)

    if last_response is None:
        result.availability_state = "DOWN"
        result.severity = "CRITICAL"
        result.response_time_ms = last_elapsed_ms
        result.issues.append(
            f"Endpoint unreachable after {result.attempts_used} attempts: {last_error}"
        )
        return result

    result.http_status = last_response.status_code
    result.final_url = last_response.url
    result.response_time_ms = last_elapsed_ms
    result.redirect_chain = [r.url for r in last_response.history] + [last_response.url]
    result.response_headers = dict(last_response.headers)
    body_text = last_response.text or ""
    result.html_snippet = body_text[:100000]

    is_waf, waf_provider, waf_detail = classify_waf_or_geoblock(
        last_response.status_code,
        result.response_headers,
        body_text,
    )
    result.waf_detected = is_waf
    result.waf_provider = waf_provider
    result.waf_detail = waf_detail

    latency_warn_ms = config.latency_warning_seconds * 1000.0

    if 200 <= last_response.status_code < 400:
        if last_elapsed_ms is not None and last_elapsed_ms > latency_warn_ms:
            result.availability_state = "DEGRADED"
            result.severity = "WARNING"
            result.issues.append(
                f"High response latency: {last_elapsed_ms:.0f} ms "
                f"(threshold: {latency_warn_ms:.0f} ms)."
            )
        else:
            result.availability_state = "UP"
            result.severity = "OK"
    elif is_waf:
        result.availability_state = "WAF_OR_GEOBLOCK"
        result.severity = "WARNING"
        result.issues.append(
            f"Non-200 HTTP {last_response.status_code} classified as WAF/Geo-Restriction "
            f"({waf_detail}). Configure MONITOR_PROXY_URL with a PH IP if full bypass is required."
        )
    elif last_response.status_code in CLOUDFLARE_ORIGIN_DOWN_CODES:
        result.availability_state = "DOWN"
        result.severity = "CRITICAL"
        result.issues.append(
            f"Cloudflare origin error HTTP {last_response.status_code}: origin web server for {url} is down or unreachable."
        )
    else:
        result.availability_state = "DOWN"
        result.severity = "CRITICAL"
        result.issues.append(
            f"Unexpected HTTP status {last_response.status_code} from {url} "
            f"(after {result.attempts_used} attempts)."
        )

    # Elevate severity if SSL or DNS reported issues
    if result.ssl and not result.ssl.valid:
        result.severity = "CRITICAL"
    elif result.ssl and result.ssl.warning and result.severity == "OK":
        result.severity = "WARNING"
    if result.dns and result.dns.has_bogon_ip:
        result.severity = "CRITICAL"

    return result
