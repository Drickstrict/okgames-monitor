"""Unit and integration tests for the OKGames.ph Daily Malware & Downtime Monitor."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from okgames_monitor.config import MonitorConfig
from okgames_monitor.malware import (
    check_google_safe_browsing,
    check_urlhaus,
    check_virustotal,
    is_allowed_domain,
    run_malware_scan,
    scan_html_and_headers,
)
from okgames_monitor.reporting import (
    build_daily_report,
    render_markdown_report,
    send_webhook_alerts,
    write_report_files,
)
from okgames_monitor.uptime import (
    DNSCheckResult,
    SSLCheckResult,
    check_endpoint_uptime,
    classify_waf_or_geoblock,
)


class TestOKGamesMonitor(unittest.TestCase):
    def test_classify_waf_or_geoblock_cloudflare_challenge(self):
        is_waf, provider, detail = classify_waf_or_geoblock(
            status_code=403,
            headers={"Server": "cloudflare", "cf-ray": "8899aabbcc-LAX", "cf-mitigated": "challenge"},
            body_text="<html><title>Just a moment...</title></html>",
        )
        self.assertTrue(is_waf)
        self.assertEqual(provider, "Cloudflare")
        self.assertIn("cf-mitigated=challenge", detail or "")

    def test_classify_waf_or_geoblock_origin_522_is_not_waf(self):
        is_waf, provider, detail = classify_waf_or_geoblock(
            status_code=522,
            headers={"Server": "cloudflare", "cf-ray": "8899aabbcc-LAX"},
            body_text="Connection timed out",
        )
        self.assertFalse(is_waf)
        self.assertEqual(provider, "Cloudflare")
        self.assertIsNone(detail)

    @patch("okgames_monitor.uptime.check_dns")
    @patch("okgames_monitor.uptime.check_ssl_certificate")
    def test_check_endpoint_uptime_healthy_and_waf_and_origin_down(self, mock_ssl, mock_dns):
        mock_dns.return_value = DNSCheckResult(
            hostname="okgames.ph",
            resolved=True,
            ip_addresses=["104.18.10.20"],
            lookup_time_ms=12.5,
        )
        mock_ssl.return_value = SSLCheckResult(
            hostname="okgames.ph",
            valid=True,
            issuer="CN=WE1, O=Google Trust Services",
            subject="CN=okgames.ph",
            days_remaining=65,
        )

        config = MonitorConfig(
            target_urls=["https://okgames.ph"],
            max_retries=2,
            retry_delay_seconds=0.0,
        )

        # 1. Healthy 200 OK
        mock_session = MagicMock()
        resp_ok = MagicMock()
        resp_ok.status_code = 200
        resp_ok.url = "https://www.okgames.ph/"
        resp_ok.history = [MagicMock(url="https://okgames.ph")]
        resp_ok.headers = {"Server": "cloudflare", "Strict-Transport-Security": "max-age=31536000"}
        resp_ok.text = "<html><head><title>OKGames Philippines</title></head><body>Welcome to OKGames</body></html>"
        mock_session.get.return_value = resp_ok

        res_ok = check_endpoint_uptime("https://okgames.ph", config, session=mock_session)
        self.assertEqual(res_ok.availability_state, "UP")
        self.assertEqual(res_ok.severity, "OK")
        self.assertEqual(res_ok.redirect_chain, ["https://okgames.ph", "https://www.okgames.ph/"])

        # 2. Cloudflare 403 WAF/Geo-Challenge -> WAF_OR_GEOBLOCK (WARNING)
        resp_waf = MagicMock()
        resp_waf.status_code = 403
        resp_waf.url = "https://okgames.ph"
        resp_waf.history = []
        resp_waf.headers = {"Server": "cloudflare", "cf-ray": "12345-SJC"}
        resp_waf.text = "<html><title>Attention Required! | Cloudflare</title></html>"
        mock_session.get.return_value = resp_waf

        res_waf = check_endpoint_uptime("https://okgames.ph", config, session=mock_session)
        self.assertEqual(res_waf.availability_state, "WAF_OR_GEOBLOCK")
        self.assertEqual(res_waf.severity, "WARNING")
        self.assertTrue(res_waf.waf_detected)

        # 3. Cloudflare 522 Origin Down -> DOWN (CRITICAL)
        resp_522 = MagicMock()
        resp_522.status_code = 522
        resp_522.url = "https://okgames.ph"
        resp_522.history = []
        resp_522.headers = {"Server": "cloudflare"}
        resp_522.text = "Origin Connection Time-out"
        mock_session.get.return_value = resp_522

        res_down = check_endpoint_uptime("https://okgames.ph", config, session=mock_session)
        self.assertEqual(res_down.availability_state, "DOWN")
        self.assertEqual(res_down.severity, "CRITICAL")
        self.assertEqual(res_down.attempts_used, 2)

    def test_scan_html_and_headers_detects_malware_and_unauthorized_scripts(self):
        config = MonitorConfig()
        malicious_html = """
        <html>
          <head>
            <script src="https://www.googletagmanager.com/gtm.js"></script>
            <script src="https://evil-skimmer-cdn.xyz/steal.js"></script>
          </head>
          <body>
            <iframe src="https://malicious-tds.ru/gate" style="display:none; width:0; height:0"></iframe>
            <script>eval(function(p,a,c,k,e,d){return p;})</script>
          </body>
        </html>
        """
        findings, missing_hdrs, ext_scripts = scan_html_and_headers(
            url="https://okgames.ph",
            html=malicious_html,
            headers={"Strict-Transport-Security": "max-age=31536000"},
            config=config,
        )

        titles = [f.title for f in findings]
        self.assertTrue(any("Obfuscated packed JS" in t for t in titles))
        self.assertTrue(any("Hidden iframe detected" in t for t in titles))
        self.assertTrue(any("evil-skimmer-cdn.xyz" in t for t in titles))
        self.assertTrue(any("malicious-tds.ru" in t for t in titles))
        self.assertIn("content-security-policy", missing_hdrs)
        self.assertEqual(len(ext_scripts), 3)

    def test_reputation_apis_urlhaus_virustotal_gsb(self):
        config = MonitorConfig(
            virustotal_api_key="test-vt-key",
            google_safe_browsing_api_key="test-gsb-key",
        )
        mock_session = MagicMock()

        # URLhaus clean
        resp_uh = MagicMock()
        resp_uh.status_code = 200
        resp_uh.json.return_value = {"query_status": "no_results"}
        mock_session.post.return_value = resp_uh
        uh_res = check_urlhaus("okgames.ph", config, session=mock_session)
        self.assertEqual(uh_res.status, "CLEAN")

        # VirusTotal clean
        resp_vt = MagicMock()
        resp_vt.status_code = 200
        resp_vt.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 72,
                        "undetected": 18,
                    }
                }
            }
        }
        mock_session.get.return_value = resp_vt
        vt_res = check_virustotal("okgames.ph", config, session=mock_session)
        self.assertEqual(vt_res.status, "CLEAN")

        # Google Safe Browsing flagged
        resp_gsb = MagicMock()
        resp_gsb.status_code = 200
        resp_gsb.json.return_value = {
            "matches": [{"threatType": "MALWARE", "threat": {"url": "https://okgames.ph"}}]
        }
        mock_session.post.return_value = resp_gsb
        gsb_res = check_google_safe_browsing(["https://okgames.ph"], config, session=mock_session)
        self.assertEqual(gsb_res.status, "FLAGGED")
        self.assertEqual(gsb_res.malicious_count, 1)

    @patch("okgames_monitor.uptime.check_dns")
    @patch("okgames_monitor.uptime.check_ssl_certificate")
    def test_end_to_end_report_and_webhook(self, mock_ssl, mock_dns):
        mock_dns.return_value = DNSCheckResult(
            hostname="okgames.ph",
            resolved=True,
            ip_addresses=["104.18.10.20"],
            lookup_time_ms=8.1,
        )
        mock_ssl.return_value = SSLCheckResult(
            hostname="okgames.ph",
            valid=True,
            days_remaining=45,
        )

        config = MonitorConfig(
            target_urls=["https://okgames.ph"],
            enable_playwright=False,
            slack_webhook_url="https://hooks.slack.com/services/T00/B00/X00",
        )

        mock_session = MagicMock()
        resp_ok = MagicMock()
        resp_ok.status_code = 200
        resp_ok.url = "https://okgames.ph/"
        resp_ok.history = []
        resp_ok.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
            "Content-Security-Policy": "default-src 'self'",
        }
        resp_ok.text = "<html><body>Welcome to OKGames</body></html>"
        resp_ok.json.return_value = {"query_status": "no_results"}
        resp_ok.ok = True
        mock_session.get.return_value = resp_ok
        mock_session.post.return_value = resp_ok

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            up_res = check_endpoint_uptime("https://okgames.ph", config, session=mock_session)
            mw_rep = run_malware_scan([up_res], config, output_dir=tmp_path, session=mock_session)
            daily = build_daily_report([up_res], mw_rep)

            self.assertEqual(daily.overall_severity, "OK")
            md = render_markdown_report(daily)
            self.assertIn("OKGames.ph Daily Security & Uptime Report", md)
            self.assertIn("🟢 HEALTHY", md)

            files = write_report_files(daily, output_dir=tmp_path, date_slug="2026-11-10")
            self.assertTrue(files["dated_md"].exists())
            self.assertTrue(files["dated_json"].exists())
            self.assertTrue(files["history_csv"].exists())

            sent = send_webhook_alerts(daily, config, session=mock_session)
            self.assertEqual(sent, ["Slack"])

    def test_is_allowed_domain(self):
        allowed = ["okgames.ph", "googletagmanager.com"]
        self.assertTrue(is_allowed_domain("okgames.ph", allowed))
        self.assertTrue(is_allowed_domain("www.okgames.ph", allowed))
        self.assertTrue(is_allowed_domain("cdn.okgames.ph", allowed))
        self.assertFalse(is_allowed_domain("fakeokgames.ph", allowed))


if __name__ == "__main__":
    unittest.main()
