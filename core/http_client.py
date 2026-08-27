"""
Shared HTTP client used by every scanner module.

Centralizes headers, cookies, proxy, and timeout handling so individual
modules (XSS, JWT, IDOR, path traversal, etc.) don't each reimplement
request plumbing — they just call .get() / .post() and get consistent
behavior everywhere.
"""

import time

import requests


class HTTPClient:
    """
    Shared HTTP client with polite-by-default request pacing.

    A small delay is applied between every request automatically, and it
    backs off further on its own if the target responds with 429 (Too Many
    Requests). This isn't configurable per-request on purpose — the goal is
    that every module built on this client is well-behaved by default,
    without anyone needing to remember to opt in. This keeps the tool
    reasonable to run against real targets (including bug bounty scope),
    where hammering a server with rapid-fire requests is against most
    programs' rules regardless of intent.
    """

    MIN_DELAY = 0.4  # seconds between requests, baseline
    BACKOFF_ON_429 = 5  # seconds to wait after a rate-limit response

    def __init__(self, headers=None, cookies=None, proxy=None, timeout=5, verify_ssl=True):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Toolkit-Scanner/1.0"})
        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.cookies.update(cookies)

        self.proxies = None
        if proxy:
            self.proxies = {"http": proxy, "https": proxy}

        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._last_request_at = None

    def get(self, url, params=None, **kwargs):
        return self._request("GET", url, params=params, **kwargs)

    def post(self, url, data=None, json=None, **kwargs):
        return self._request("POST", url, data=data, json=json, **kwargs)

    def _pace(self):
        """Sleep just enough to keep requests spaced out politely."""
        if self._last_request_at is not None:
            elapsed = time.monotonic() - self._last_request_at
            remaining = self.MIN_DELAY - elapsed
            if remaining > 0:
                time.sleep(remaining)

    def _request(self, method, url, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_ssl)
        if self.proxies:
            kwargs.setdefault("proxies", self.proxies)

        self._pace()
        try:
            response = self.session.request(method, url, **kwargs)
        except requests.RequestException as e:
            print(f"[-] Request error ({method} {url}): {e}")
            self._last_request_at = time.monotonic()
            return None

        self._last_request_at = time.monotonic()

        if response.status_code == 429:
            print(f"[!] Rate limited (429) on {url} — backing off for {self.BACKOFF_ON_429}s")
            time.sleep(self.BACKOFF_ON_429)

        return response


def parse_headers(header_args):
    """Turn a list of 'Key: Value' strings into a dict."""
    headers = {}
    if not header_args:
        return headers
    for h in header_args:
        if ":" not in h:
            print(f"[-] Ignoring malformed header (expected 'Key: Value'): {h}")
            continue
        key, value = h.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers


def parse_cookie_string(cookie_string):
    """Turn 'name1=value1; name2=value2' into a dict."""
    cookies = {}
    if not cookie_string:
        return cookies
    for part in cookie_string.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        cookies[name.strip()] = value.strip()
    return cookies


def load_wordlist(path):
    """Load a wordlist file, one entry per line. Lines starting with # are ignored."""
    entries = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    entries.append(line)
    except OSError as e:
        print(f"[-] Could not read wordlist '{path}': {e}")
        return None

    if not entries:
        print(f"[-] Wordlist '{path}' is empty.")
        return None

    return entries
