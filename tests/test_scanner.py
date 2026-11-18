"""Run from the project folder:  python -m unittest -v"""
import threading
import unittest

from requests.structures import CaseInsensitiveDict
from werkzeug.serving import make_server

import config
from scanner import checks
from scanner.engine import Hop, run_scan
from scanner.policy import TargetRejected, validate_url
import test_server


def hop(headers=None, cookies=None, url="http://127.0.0.1/"):
    return Hop(url, 200, CaseInsensitiveDict(headers or {}), cookies or [])


class PolicyTests(unittest.TestCase):
    def test_valid_local(self):
        self.assertEqual(validate_url("http://127.0.0.1:5001/"), "http://127.0.0.1:5001/")

    def test_rejects_bad(self):
        for bad in ["", "ftp://localhost/", "http://example.com/", "http://user:pw@localhost/",
                    "http://localhost:99999/", "not a url", "http://192.168.1.1/"]:
            with self.assertRaises(TargetRejected, msg=bad):
                validate_url(bad)


class HeaderTests(unittest.TestCase):
    def status(self, findings, name):
        return [f["status"] for f in findings if f["check_name"] == name][0]

    def test_missing(self):
        f = checks.check_headers(hop())
        for n in ("header_csp", "header_xcto", "header_referrer", "header_frame"):
            self.assertEqual(self.status(f, n), "Fail")

    def test_present(self):
        h = {"Content-Security-Policy": "default-src 'self'", "X-Content-Type-Options": "nosniff",
             "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY"}
        f = checks.check_headers(hop(h))
        for n in ("header_csp", "header_xcto", "header_referrer", "header_frame"):
            self.assertEqual(self.status(f, n), "Pass")

    def test_hsts_only_on_https(self):
        self.assertEqual(self.status(checks.check_headers(hop()), "header_hsts"), "Info")
        self.assertEqual(self.status(checks.check_headers(hop(url="https://127.0.0.1/")), "header_hsts"), "Fail")


class CookieTests(unittest.TestCase):
    def test_bad_cookie_and_no_value_leak(self):
        f = checks.check_cookies(hop(cookies=["sid=TOPSECRET; Path=/"]))
        self.assertEqual({x["check_name"]: x["status"] for x in f},
                         {"cookie_secure": "Fail", "cookie_httponly": "Fail", "cookie_samesite": "Fail"})
        self.assertNotIn("TOPSECRET", str(f))

    def test_good_cookie(self):
        f = checks.check_cookies(hop(cookies=["sid=x; Secure; HttpOnly; SameSite=Lax"]))
        self.assertTrue(all(x["status"] == "Pass" for x in f))


class DisclosureTests(unittest.TestCase):
    def test_version(self):
        f = checks.check_server_disclosure(hop({"Server": "Apache/2.4.41"}))
        self.assertEqual(f[0]["status"], "Fail")

    def test_none(self):
        self.assertEqual(checks.check_server_disclosure(hop())[0]["status"], "Pass")


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = make_server("127.0.0.1", 5055, test_server.lab, threaded=True)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_insecure_scan(self):
        findings, status, _ = run_scan("http://127.0.0.1:5055/insecure")
        self.assertEqual(status, "Completed")
        titles = " ".join(f["title"] for f in findings)
        self.assertIn("HTTPS is not available", titles)
        self.assertIn("version disclosed", titles)

    def test_secure_scan_headers_pass(self):
        findings, status, _ = run_scan("http://127.0.0.1:5055/secure")
        self.assertEqual(status, "Completed")
        self.assertTrue(all(f["status"] == "Pass" for f in findings if f["category"] in ("Cookies",)))

    def test_redirect_out_of_scope_blocked(self):
        findings, status, _ = run_scan("http://127.0.0.1:5055/redirect-out")
        self.assertIn("Redirect left the approved scope", [f["title"] for f in findings])

    def test_timeout_and_unreachable(self):
        self.assertEqual(run_scan("http://127.0.0.1:5055/slow")[1], "Failed")
        self.assertEqual(run_scan("http://127.0.0.1:5999/")[1], "Failed")


if __name__ == "__main__":
    unittest.main()
