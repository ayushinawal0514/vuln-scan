"""Target policy: URL validation, host allowlist and restricted-destination blocking."""
import ipaddress
import socket
from urllib.parse import urlparse

import config


class TargetRejected(Exception):
    """Raised when a URL violates the target policy."""


def validate_url(url: str) -> str:
    url = (url or "").strip()
    if not url or len(url) > 2048:
        raise TargetRejected("URL is empty or too long.")
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise TargetRejected("Only http:// and https:// URLs are allowed.")
    if not p.hostname:
        raise TargetRejected("URL has no hostname.")
    if p.username or p.password:
        raise TargetRejected("URLs with embedded credentials are not allowed.")
    try:
        _ = p.port
    except ValueError:
        raise TargetRejected("URL has an invalid port.")

    host = p.hostname.lower()
    if host not in config.ALLOWED_HOSTS:
        raise TargetRejected(
            f"Host '{host}' is not on the approved allowlist. Only localhost and explicitly "
            f"configured lab hosts can be scanned.")
    _check_resolved_ips(host)
    return url


def _check_resolved_ips(host: str) -> None:
    """Block private/restricted addresses unless the host was explicitly enabled as a lab host."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise TargetRejected(f"Host '{host}' could not be resolved.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_loopback:
            continue
        if host in config.LAB_HOSTS:
            continue  # explicitly enabled local-lab target
        raise TargetRejected(f"'{host}' resolves to a restricted address ({ip}) and is not an enabled lab host.")
