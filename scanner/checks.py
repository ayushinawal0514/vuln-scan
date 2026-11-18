"""Individual security checks. Every check returns a list of finding dicts."""
import re
from urllib.parse import urlparse

from scanner.severity import RULES

REDIRECT_CODES = (301, 302, 303, 307, 308)


def make(check, category, title, status, rule, evidence, explanation, recommendation):
    """Build the common result format: check, status, severity, evidence, explanation, remediation."""
    if status == "Pass":
        severity, reason = "Informational", "Check passed; no rule triggered."
    else:
        severity, reason = RULES[rule]
    return {
        "check_name": check, "category": category, "title": title, "status": status,
        "severity": severity, "evidence": evidence, "explanation": explanation,
        "recommendation": recommendation, "rule_reason": reason,
    }


NOTE = " This is a potential finding and should be verified manually."


# ---------------------------------------------------------------- HTTPS / redirects
def check_https(https_fetch):
    out, ok = [], bool(https_fetch.chain)
    if not ok:
        out.append(make("https_availability", "Transport security", "HTTPS is not available", "Fail",
                        "HTTPS_UNAVAILABLE", f"HTTPS request failed: {https_fetch.error or 'no response'}",
                        "The site could not be reached over HTTPS." + NOTE,
                        "Enable HTTPS with a valid TLS certificate and serve the application over it."))
        return out, False
    out.append(make("https_availability", "Transport security", "HTTPS is available", "Pass", None,
                    f"HTTPS responded with HTTP {https_fetch.chain[0].status}.",
                    "The server accepts HTTPS connections.", "No action needed."))
    if https_fetch.tls_error:
        out.append(make("tls_certificate", "Transport security", "TLS certificate could not be verified", "Fail",
                        "TLS_CERT_INVALID", https_fetch.tls_error,
                        "The certificate is self-signed, expired, or issued for another name. "
                        "(Expected for local labs.)" + NOTE,
                        "Use a certificate from a trusted CA that matches the hostname."))
    return out, True


def check_redirect(http_fetch, https_ok):
    if not https_ok:
        return [make("http_to_https_redirect", "Transport security", "HTTP-to-HTTPS redirect not evaluated", "Info",
                     "REDIRECT_NA", "HTTPS was not reachable.", "Redirect behaviour is only judged when HTTPS exists.",
                     "Enable HTTPS first, then redirect HTTP to it.")]
    if not http_fetch.chain:
        return [make("http_to_https_redirect", "Transport security", "HTTP endpoint unreachable", "Info",
                     "REDIRECT_NA", f"HTTP request failed: {http_fetch.error}", "No HTTP response to evaluate.",
                     "None required if HTTP is intentionally disabled.")]
    hop = http_fetch.chain[0]
    loc = hop.headers.get("Location", "")
    if hop.status in REDIRECT_CODES and loc.lower().startswith("https://"):
        return [make("http_to_https_redirect", "Transport security", "HTTP redirects to HTTPS", "Pass", None,
                     f"HTTP {hop.status} -> {loc}", "Plain-HTTP requests are upgraded to HTTPS.", "No action needed.")]
    if hop.status in REDIRECT_CODES:
        return [make("http_to_https_redirect", "Transport security", "HTTP redirect does not go to HTTPS", "Fail",
                     "REDIRECT_NOT_HTTPS", f"HTTP {hop.status} -> {loc}",
                     "The redirect target is not an https:// URL." + NOTE,
                     "Redirect all HTTP requests to the https:// version of the same URL.")]
    return [make("http_to_https_redirect", "Transport security", "HTTP is served without redirecting to HTTPS", "Fail",
                 "NO_HTTP_REDIRECT", f"HTTP request returned status {hop.status} with no redirect.",
                 "The site is reachable over HTTPS but plain HTTP is not upgraded." + NOTE,
                 "Add a permanent (301/308) redirect from HTTP to HTTPS.")]


def check_redirect_scope(main):
    if not main.blocked:
        return []
    return [make("redirect_scope", "Scan scope", "Redirect left the approved scope", "Fail", "REDIRECT_OUT_OF_SCOPE",
                 main.blocked, "The scanner refused to follow a redirect to a non-approved destination." + NOTE,
                 "Review where the application redirects; no change needed for scanner safety.")]


# ---------------------------------------------------------------- security headers
def check_headers(hop):
    h, ev_base, out = hop.headers, f"Response from {hop.url} (HTTP {hop.status})", []
    https = urlparse(hop.url).scheme == "https"

    csp = h.get("Content-Security-Policy")
    if csp is None:
        out.append(make("header_csp", "Security headers", "Content-Security-Policy header missing", "Fail",
                        "MISSING_CSP", f"{ev_base}: header absent.",
                        "CSP limits where scripts and other resources can load from." + NOTE,
                        "Add a restrictive Content-Security-Policy, e.g. \"default-src 'self'\"."))
    elif re.search(r"unsafe-(inline|eval)", csp):
        out.append(make("header_csp", "Security headers", "Content-Security-Policy contains unsafe directives", "Fail",
                        "WEAK_CSP", f"Content-Security-Policy: {csp[:200]}",
                        "'unsafe-inline'/'unsafe-eval' weaken CSP." + NOTE,
                        "Remove unsafe-* sources; use nonces or hashes instead."))
    else:
        out.append(make("header_csp", "Security headers", "Content-Security-Policy header present", "Pass", None,
                        f"Content-Security-Policy: {csp[:200]}",
                        "Header presence alone does not prove the policy is effective.", "Review policy contents periodically."))

    hsts = h.get("Strict-Transport-Security")
    if not https:
        out.append(make("header_hsts", "Security headers", "HSTS not evaluated (response was not HTTPS)", "Info",
                        "HSTS_NA", f"{ev_base} was served over HTTP.", "HSTS is ignored by browsers over plain HTTP.",
                        "Serve HTTPS and add Strict-Transport-Security."))
    elif hsts is None:
        out.append(make("header_hsts", "Security headers", "Strict-Transport-Security header missing", "Fail",
                        "MISSING_HSTS", f"{ev_base}: header absent.", "HSTS tells browsers to only use HTTPS." + NOTE,
                        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."))
    else:
        m = re.search(r"max-age=(\d+)", hsts, re.I)
        if not m or int(m.group(1)) < 15552000:
            out.append(make("header_hsts", "Security headers", "HSTS max-age is short", "Fail", "WEAK_HSTS",
                            f"Strict-Transport-Security: {hsts}", "max-age is under 6 months." + NOTE,
                            "Use max-age of at least 31536000 (1 year)."))
        else:
            out.append(make("header_hsts", "Security headers", "Strict-Transport-Security header present", "Pass", None,
                            f"Strict-Transport-Security: {hsts}", "HSTS is configured.", "No action needed."))

    xcto = h.get("X-Content-Type-Options")
    if xcto is None:
        out.append(make("header_xcto", "Security headers", "X-Content-Type-Options header missing", "Fail", "MISSING_XCTO",
                        f"{ev_base}: header absent.", "Stops browsers from MIME-sniffing." + NOTE,
                        "Add 'X-Content-Type-Options: nosniff'."))
    elif xcto.strip().lower() != "nosniff":
        out.append(make("header_xcto", "Security headers", "X-Content-Type-Options has unexpected value", "Fail",
                        "WRONG_XCTO", f"X-Content-Type-Options: {xcto}", "The only valid value is 'nosniff'." + NOTE,
                        "Set the header to 'nosniff'."))
    else:
        out.append(make("header_xcto", "Security headers", "X-Content-Type-Options is 'nosniff'", "Pass", None,
                        f"X-Content-Type-Options: {xcto}", "MIME sniffing is disabled.", "No action needed."))

    ref = h.get("Referrer-Policy")
    if ref is None:
        out.append(make("header_referrer", "Security headers", "Referrer-Policy header missing", "Fail", "MISSING_REFERRER",
                        f"{ev_base}: header absent.", "Controls how much URL information is sent to other sites." + NOTE,
                        "Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter."))
    else:
        out.append(make("header_referrer", "Security headers", "Referrer-Policy header present", "Pass", None,
                        f"Referrer-Policy: {ref}", "A referrer policy is set.", "Review the chosen value."))

    xfo = h.get("X-Frame-Options")
    has_fa = csp is not None and "frame-ancestors" in csp.lower()
    if xfo is None and not has_fa:
        out.append(make("header_frame", "Security headers", "No frame-embedding protection", "Fail", "MISSING_FRAME",
                        f"{ev_base}: neither X-Frame-Options nor CSP frame-ancestors found.",
                        "Without it, other sites may embed this page in a frame (clickjacking)." + NOTE,
                        "Add CSP 'frame-ancestors 'none'' (or 'self') or 'X-Frame-Options: DENY'."))
    else:
        used = f"X-Frame-Options: {xfo}" if xfo else "CSP frame-ancestors"
        out.append(make("header_frame", "Security headers", "Frame-embedding protection present", "Pass", None,
                        used, "Framing policy is set.", "No action needed."))
    return out


# ---------------------------------------------------------------- cookies
def parse_set_cookie(raw):
    """Return (name, {attr: value}). The cookie VALUE is deliberately discarded."""
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return name, attrs


def check_cookies(hop):
    cookies = [parse_set_cookie(c) for c in hop.set_cookies]
    if not cookies:
        return [make("cookie_attributes", "Cookies", "No cookies set", "Info", "NO_COOKIES",
                     "No Set-Cookie header in the response.", "Nothing to check.", "None required.")]
    out = []
    specs = [("secure", "Secure", "COOKIE_NO_SECURE", "Add the Secure attribute so cookies are only sent over HTTPS."),
             ("httponly", "HttpOnly", "COOKIE_NO_HTTPONLY", "Add HttpOnly so JavaScript cannot read the cookie."),
             ("samesite", "SameSite", "COOKIE_NO_SAMESITE", "Add SameSite=Lax (or Strict) to the cookie.")]
    for key, label, rule, fix in specs:
        missing = [n for n, a in cookies if key not in a]
        if missing:
            out.append(make(f"cookie_{key}", "Cookies", f"Cookie(s) missing {label} attribute", "Fail", rule,
                            f"Cookie names without {label}: {', '.join(missing)} (values not stored)",
                            f"{len(missing)} of {len(cookies)} cookie(s) lack {label}." + NOTE, fix))
        else:
            out.append(make(f"cookie_{key}", "Cookies", f"All cookies have {label}", "Pass", None,
                            f"Checked {len(cookies)} cookie(s): {', '.join(n for n, _ in cookies)}",
                            f"{label} is set on every cookie.", "No action needed."))
    return out


# ---------------------------------------------------------------- information disclosure
DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"]


def check_server_disclosure(hop):
    seen = [(n, hop.headers.get(n)) for n in DISCLOSURE_HEADERS if hop.headers.get(n)]
    if not seen:
        return [make("server_disclosure", "Information disclosure", "No server/technology headers exposed", "Pass", None,
                     "None of " + ", ".join(DISCLOSURE_HEADERS) + " present.", "No product details leaked.", "No action needed.")]
    evidence = "; ".join(f"{n}: {v}" for n, v in seen)
    if any(re.search(r"\d+\.\d+", v) or "/" in v and re.search(r"\d", v) for _, v in seen):
        return [make("server_disclosure", "Information disclosure", "Server/technology version disclosed", "Fail",
                     "SERVER_VERSION", evidence, "Headers reveal product and version information." + NOTE,
                     "Remove or genericise these headers (e.g. 'ServerTokens Prod' in Apache, 'server_tokens off' in nginx).")]
    return [make("server_disclosure", "Information disclosure", "Server/technology header present (no version)", "Info",
                 "SERVER_PRESENT", evidence, "A product name is exposed but no version.", "Consider removing the header.")]
