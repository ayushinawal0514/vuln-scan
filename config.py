"""Central configuration and safety limits for the scanner."""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scans.db")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-me")

# ---- Target policy -------------------------------------------------------
# Only these hosts can ever be scanned. Add your own authorized lab host via
# the environment variable LAB_HOSTS="myLab.local,192.168.56.101".
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
LAB_HOSTS = {h.strip().lower() for h in os.environ.get("LAB_HOSTS", "").split(",") if h.strip()}
ALLOWED_HOSTS = LOOPBACK_HOSTS | LAB_HOSTS

# ---- Request safety limits ----------------------------------------------
REQUEST_TIMEOUT = 5            # seconds per request
MAX_REQUESTS_PER_SCAN = 12     # hard cap on HTTP requests per scan
MAX_REDIRECTS = 3
USER_AGENT = "ET401-VulnScanner/1.0 (educational; authorized testing only)"

SCOPE_TEXT = ("This scan was run only against a target owned by the developer or one for which "
              "explicit permission exists. Only low-volume, read-only HTTP GET requests were made.")
LIMITATIONS = [
    "Only a limited set of configuration checks is performed (HTTPS, redirects, security headers, "
    "cookie attributes, server-information disclosure).",
    "Results are potential findings and need manual verification; false positives are possible.",
    "A missing header is a configuration observation, not proof of a vulnerability; the presence of a "
    "header is not proof of a secure configuration.",
    "Severity labels are a simple rule-based classification. They are NOT CVSS scores and are not a "
    "probability of compromise.",
    "A scan with no findings does not prove the application is secure.",
]
