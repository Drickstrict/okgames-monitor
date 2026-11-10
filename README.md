# OKGames.ph Daily Malware & Downtime Monitor

Automated daily availability, SSL/DNS health, WAF/Geo-restriction classification, and multi-layered malware monitoring suite for **`OKGames.ph`** (`https://okgames.ph` and `https://www.okgames.ph`).

---

## Features & Architecture

1. **Daily Scheduled Execution (`8:00 AM PHT` / `00:00 UTC`) + On-Demand Dispatch**
   - Runs automatically via [`.github/workflows/daily-monitor.yml`](.github/workflows/daily-monitor.yml) every morning at **8:00 AM Philippine Time (`00:00 UTC`)**, and supports one-click manual runs via `workflow_dispatch`.

2. **Full Availability & WAF-Aware Uptime Suite ([`okgames_monitor/uptime.py`](okgames_monitor/uptime.py))**
   - **HTTP Status & Redirect Chain Tracking**: Follows redirects (`https://okgames.ph` -> `https://www.okgames.ph`), checks status codes, and retries up to **3 times** (10s interval) before declaring downtime.
   - **Response Latency Threshold**: Flags degraded performance if response time exceeds **5.0 seconds**.
   - **SSL/TLS Certificate Verification**: Verifies TLS handshake, certificate chain validity, and alerts when expiry is within **14 days**.
   - **DNS Resolution & Bogon/Hijack Check**: Resolves `A`/`AAAA` records and verifies no private/reserved bogon IPs are returned.
   - **Cloudflare / WAF / Geo-Restriction Classifier**: Explicitly distinguishes between:
     - `UP`: Standard `2xx`/`3xx` response within latency thresholds.
     - `WAF_OR_GEOBLOCK` (`WARNING`): Non-200 (`403`/`503`) returned by Cloudflare/WAF bot challenge or PH geo-restriction when accessed from US/global GitHub Actions runner IPs, while confirming DNS and TLS edge health. Supports optional `MONITOR_PROXY_URL` secret for Philippine residential/proxy routing.
     - `DOWN` (`CRITICAL`): Origin server errors (`5xx`, Cloudflare `520`–`526` origin unreachable), connection timeouts, or DNS failures.

3. **3-Layer Malware & Security Scanner ([`okgames_monitor/malware.py`](okgames_monitor/malware.py))**
   - **Layer 1 — Static Heuristic DOM & Security Header Scan**: Inspects HTML for obfuscated JavaScript packers (`eval(function(p,a,c,k,e,d))`), `document.write(unescape(...))` injections, hidden zero-size `<iframe>` tags, crypto-miner scripts, defacement signatures, unauthorized external script/iframe domains, and missing HTTP security headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`).
   - **Layer 2 — Deep Headless Browser Inspection (Playwright Chromium)**: Renders the live site in headless Chromium (`Asia/Manila` timezone, `en-PH` locale), records all runtime network requests and third-party domains contacted, detects unauthorized runtime redirects or dynamically injected DOM scripts, and captures full-page screenshots (`reports/screenshots/*.png`).
   - **Layer 3 — Public Blocklists & Threat Intelligence APIs**:
     - **URLhaus (`abuse.ch`)**: Checks whether `okgames.ph` has any listed malware distribution URLs.
     - **VirusTotal v3 API** *(optional secret `VIRUSTOTAL_API_KEY`)*: Queries 70+ security vendor engines for domain reputation.
     - **Google Safe Browsing v4 API** *(optional secret `GOOGLE_SAFE_BROWSING_API_KEY`)*: Checks URLs against Google's `MALWARE`, `SOCIAL_ENGINEERING`, and `UNWANTED_SOFTWARE` lists.

4. **Multi-Destination Reporting & Automated Alerting ([`okgames_monitor/reporting.py`](okgames_monitor/reporting.py))**
   - **GitHub Actions Job Summary & Artifacts**: Publishes a rich Markdown dashboard directly on every workflow run and uploads dated Markdown (`okgames-report-YYYY-MM-DD.md`), JSON (`okgames-report-YYYY-MM-DD.json`), cumulative `okgames-history.csv`, and Playwright screenshots for 90 days.
   - **Google Drive Sync (`OKGames` Folder `1quiLsHcrWb4JtKEGACsc4KVWBEGC0Nm9`)**: Automatically uploads daily report files to the `OKGames` Google Drive folder via Service Account (`GDRIVE_SERVICE_ACCOUNT_JSON`) or local `gdrive` CLI.
   - **Automated GitHub Issue Management**: Automatically opens or updates an issue labeled `okgames-monitor-alert` on `CRITICAL` or `WARNING` states, and automatically comments & closes the issue when `OKGames.ph` recovers to `OK`.
   - **Webhook Alerts**: Supports optional Slack (`SLACK_WEBHOOK_URL`), Discord (`DISCORD_WEBHOOK_URL`), and Telegram (`TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`) notifications.

---

## Quick Start (Local Usage)

```bash
# Install dependencies
pip install -r requirements.txt
playwright install chromium

# Run full daily check (Uptime + Heuristics + Playwright + Blocklists) and upload to Google Drive
python -m okgames_monitor.cli --output-dir ./reports --upload-gdrive

# Run fast check without Playwright
python -m okgames_monitor.cli --output-dir ./reports --skip-playwright

# Run test suite
pytest -v
```

---

## GitHub Actions Setup & Optional Secrets

Push this repository to GitHub. The workflow in [`.github/workflows/daily-monitor.yml`](.github/workflows/daily-monitor.yml) works out-of-the-box with **zero required secrets** and can be enhanced by adding any of the following optional repository secrets under **Settings -> Secrets and variables -> Actions**:

| Secret Name | Required? | Description |
| :--- | :--- | :--- |
| `VIRUSTOTAL_API_KEY` | Optional | Free VirusTotal v3 API key for 70+ engine domain reputation scanning |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Optional | Google Cloud Safe Browsing v4 API key |
| `URLHAUS_AUTH_KEY` | Optional | `abuse.ch` Auth-Key for URLhaus host lookups |
| `MONITOR_PROXY_URL` | Optional | Philippine HTTP/SOCKS5 proxy URL (e.g., `http://user:pass@ph-proxy:8080`) if `OKGames.ph` blocks non-PH datacenter IPs |
| `GDRIVE_SERVICE_ACCOUNT_JSON` | Optional | Google Cloud Service Account JSON key (shared with the `OKGames` Drive folder `1quiLsHcrWb4JtKEGACsc4KVWBEGC0Nm9`) for automated Drive uploads from GitHub Actions |
| `SLACK_WEBHOOK_URL` | Optional | Slack Incoming Webhook URL for instant alerts |
| `DISCORD_WEBHOOK_URL` | Optional | Discord Channel Webhook URL for instant alerts |
| `TELEGRAM_BOT_TOKEN` | Optional | Telegram Bot Token from `@BotFather` |
| `TELEGRAM_CHAT_ID` | Optional | Telegram Group/Channel Chat ID for alerts |
