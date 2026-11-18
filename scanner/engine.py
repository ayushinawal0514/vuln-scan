"""Scan controller + safe HTTP client (timeouts, request cap, manual redirect validation)."""
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urlunparse

import requests
import urllib3
from requests.structures import CaseInsensitiveDict

import config
from scanner import checks
from scanner.policy import TargetRejected, validate_url
from scanner.checks import make

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class BudgetExceeded(Exception):
    pass


@dataclass
class Hop:
    url: str
    status: int
    headers: CaseInsensitiveDict
    set_cookies: list


@dataclass
class Fetched:
    chain: list = field(default_factory=list)
    error: str = None
    tls_error: str = None
    blocked: str = None


class SafeClient:
    def __init__(self):
        self.count = 0
        self.session = requests.Session()
        self.session.trust_env = False

    def _request(self, url):
        tls_error, verify = None, True
        while True:
            if self.count >= config.MAX_REQUESTS_PER_SCAN:
                raise BudgetExceeded()
            self.count += 1
            try:
                r = self.session.get(url, timeout=config.REQUEST_TIMEOUT, allow_redirects=False, verify=verify,
                                     stream=True, headers={"User-Agent": config.USER_AGENT})
                break
            except requests.exceptions.SSLError as e:
                if verify and "CERTIFICATE_VERIFY_FAILED" in str(e):
                    tls_error, verify = "Certificate verification failed (self-signed, expired or name mismatch).", False
                    continue
                raise
        try:
            cookies = r.raw.headers.getlist("Set-Cookie")
        except AttributeError:
            v = r.headers.get("Set-Cookie")
            cookies = [v] if v else []
        hop = Hop(url, r.status_code, CaseInsensitiveDict(r.headers), list(cookies))
        r.close()
        self.session.cookies.clear()          # never keep cookies between requests
        return hop, tls_error

    def fetch(self, url, follow=True):
        res, current = Fetched(), url
        for _ in range(config.MAX_REDIRECTS + 1):
            try:
                validate_url(current)
            except TargetRejected as e:
                res.blocked = f"Request to {current} blocked by target policy: {e}"
                return res
            try:
                hop, tls = self._request(current)
            except BudgetExceeded:
                res.error = "Per-scan request limit reached."
                return res
            except requests.exceptions.Timeout:
                res.error = f"Timed out after {config.REQUEST_TIMEOUT}s."
                return res
            except requests.exceptions.RequestException as e:
                res.error = f"{type(e).__name__}: {str(e)[:120]}"
                return res
            res.tls_error = res.tls_error or tls
            res.chain.append(hop)
            loc = hop.headers.get("Location")
            if not follow or hop.status not in checks.REDIRECT_CODES or not loc:
                return res
            current = urljoin(current, loc)
        res.error = "Too many redirects."
        return res


def _with_scheme(url, scheme):
    return urlunparse(urlparse(url)._replace(scheme=scheme))


def run_scan(target_url):
    """Run all checks. Returns (findings, status, error_message)."""
    target_url = validate_url(target_url)
    client = SafeClient()
    main = client.fetch(target_url)
    if not main.chain:
        msg = main.blocked or main.error or "No response."
        return ([make("scan", "Scan", "Target could not be scanned", "Info", "SCAN_ERROR", msg,
                      "The target was unreachable, timed out or was blocked.",
                      "Check the URL and that the target is running.")], "Failed", msg)

    findings = []
    final = main.chain[-1]
    findings += checks.check_redirect_scope(main)

    # HTTPS availability
    if urlparse(final.url).scheme == "https":
        https_fetch = main
    else:
        https_fetch = client.fetch(_with_scheme(target_url, "https"), follow=False)
    https_findings, https_ok = checks.check_https(https_fetch)
    findings += https_findings

    # HTTP -> HTTPS redirect
    http_fetch = main if urlparse(target_url).scheme == "http" else client.fetch(_with_scheme(target_url, "http"), follow=False)
    findings += checks.check_redirect(http_fetch, https_ok)

    # Response-level checks on the final response
    findings += checks.check_headers(final)
    findings += checks.check_cookies(final)
    findings += checks.check_server_disclosure(final)
    return findings, "Completed", None
