"""HTTP client abstraction that uses `requests` when installed and falls back to `urllib.request`."""

from __future__ import annotations

import json as _json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class HistoryEntry:
    url: str
    status_code: int = 302


@dataclass
class HttpResponse:
    status_code: int
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    text: str = ""
    history: List[HistoryEntry] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    def json(self) -> Any:
        return _json.loads(self.text or "{}")

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code} Error for URL: {self.url}")


class _RedirectTracker(urllib.request.HTTPRedirectHandler):
    def __init__(self) -> None:
        super().__init__()
        self.history: List[HistoryEntry] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.history.append(HistoryEntry(url=req.full_url, status_code=code))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class StdlibSession:
    """Drop-in subset of `requests.Session` powered by Python's standard library."""

    def _request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
        timeout: float = 20.0,
        allow_redirects: bool = True,
        proxies: Optional[Dict[str, str]] = None,
    ) -> HttpResponse:
        req_headers = dict(headers or {})
        body_bytes: Optional[bytes] = None

        if json is not None:
            body_bytes = _json.dumps(json).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")
        elif data is not None:
            body_bytes = urllib.parse.urlencode(data).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

        tracker = _RedirectTracker()
        handlers: List[Any] = []
        if proxies:
            handlers.append(urllib.request.ProxyHandler(proxies))
        if allow_redirects:
            handlers.append(tracker)

        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method)

        try:
            with opener.open(req, timeout=timeout) as resp:
                raw = resp.read()
                text = raw.decode("utf-8", errors="replace")
                resp_headers = {k: v for k, v in resp.headers.items()}
                return HttpResponse(
                    status_code=resp.status,
                    url=resp.geturl(),
                    headers=resp_headers,
                    text=text,
                    history=list(tracker.history),
                )
        except urllib.error.HTTPError as err:
            raw = err.read() if err.fp else b""
            text = raw.decode("utf-8", errors="replace")
            resp_headers = {k: v for k, v in err.headers.items()} if err.headers else {}
            return HttpResponse(
                status_code=err.code,
                url=err.geturl() or url,
                headers=resp_headers,
                text=text,
                history=list(tracker.history),
            )

    def get(self, url: str, **kwargs: Any) -> HttpResponse:
        return self._request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> HttpResponse:
        return self._request("POST", url, **kwargs)


def create_http_session() -> Any:
    """Return a `requests.Session` if `requests` is installed, else `StdlibSession`."""
    try:
        import requests  # type: ignore

        return requests.Session()
    except ImportError:
        return StdlibSession()
