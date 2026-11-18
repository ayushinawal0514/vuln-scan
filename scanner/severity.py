"""Rule-based severity labels, each with a written reason. NOT CVSS."""

SEVERITY_ORDER = ["High", "Medium", "Low", "Informational"]

RULES = {
    "HTTPS_UNAVAILABLE": ("Medium", "Without HTTPS, traffic can be read or modified by anyone on the network path."),
    "TLS_CERT_INVALID": ("Medium", "An untrusted certificate prevents clients from verifying the server identity."),
    "NO_HTTP_REDIRECT": ("Medium", "HTTP stays usable although HTTPS exists, so users may stay on an unencrypted connection."),
    "REDIRECT_NOT_HTTPS": ("Medium", "The HTTP endpoint redirects, but not to an HTTPS address."),
    "REDIRECT_NA": ("Informational", "Redirect behaviour could not be evaluated because HTTPS was not reachable."),
    "REDIRECT_OUT_OF_SCOPE": ("Low", "A redirect pointed outside the approved scope; the scanner refused to follow it."),
    "MISSING_CSP": ("Medium", "No Content-Security-Policy removes a major browser defence layer against script injection."),
    "WEAK_CSP": ("Low", "A CSP containing unsafe-inline / unsafe-eval weakens its protection."),
    "MISSING_HSTS": ("Medium", "Without HSTS, browsers may be downgraded to HTTP (SSL-stripping)."),
    "WEAK_HSTS": ("Low", "A short HSTS max-age gives limited protection."),
    "HSTS_NA": ("Informational", "HSTS is only meaningful on HTTPS responses; this response was not HTTPS."),
    "MISSING_XCTO": ("Low", "Without 'nosniff', browsers may MIME-sniff responses into executable types."),
    "WRONG_XCTO": ("Low", "X-Content-Type-Options is present but not set to 'nosniff'."),
    "MISSING_REFERRER": ("Low", "Without Referrer-Policy, full URLs may leak to other sites."),
    "MISSING_FRAME": ("Medium", "No frame-embedding policy allows clickjacking from other sites."),
    "COOKIE_NO_SECURE": ("Medium", "Cookies without Secure can be sent over unencrypted HTTP."),
    "COOKIE_NO_HTTPONLY": ("Medium", "Cookies without HttpOnly are readable by JavaScript (XSS impact)."),
    "COOKIE_NO_SAMESITE": ("Low", "Cookies without SameSite rely on browser defaults for CSRF protection."),
    "NO_COOKIES": ("Informational", "No cookies were set by this response, so no cookie attributes could be checked."),
    "SERVER_VERSION": ("Low", "Product/version details help an attacker pick known exploits."),
    "SERVER_PRESENT": ("Informational", "A server/technology header is present but shows no version number."),
    "SCAN_ERROR": ("Informational", "The scan could not complete; this is not a security finding."),
}


def rule_severity(rule_id):
    return RULES[rule_id]


def risk_summary(findings):
    """Highest severity among failed checks (simple rule-based summary, not CVSS)."""
    failed = [f["severity"] for f in findings if f["status"] == "Fail"]
    for s in SEVERITY_ORDER:
        if s in failed:
            return s
    return "None"
