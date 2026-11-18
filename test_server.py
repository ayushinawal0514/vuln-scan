"""Local lab target with KNOWN response configurations (run this, then scan http://127.0.0.1:5001/...)."""
import time
from flask import Flask, make_response, redirect

lab = Flask(__name__)


@lab.route("/")
def index():
    return ('<h2>ET401 Lab Target</h2><ul><li>/secure</li><li>/insecure</li>'
            '<li>/redirect-local</li><li>/redirect-out</li><li>/slow</li></ul>')


@lab.route("/secure")
def secure():
    r = make_response("secure page")
    r.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Server"] = "lab"
    r.headers.add("Set-Cookie", "session=SECRETVALUE123; Path=/; Secure; HttpOnly; SameSite=Lax")
    return r


@lab.route("/insecure")
def insecure():
    r = make_response("insecure page")
    r.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
    r.headers["X-Powered-By"] = "PHP/7.4.3"
    r.headers.add("Set-Cookie", "sid=SECRETVALUE456; Path=/")
    r.headers.add("Set-Cookie", "theme=dark; Path=/; HttpOnly")
    return r


@lab.route("/redirect-local")
def redirect_local():
    return redirect("/secure", 302)


@lab.route("/redirect-out")
def redirect_out():
    return redirect("http://example.com/", 302)       # leaves approved scope -> scanner must refuse


@lab.route("/slow")
def slow():
    time.sleep(8)                                       # longer than the 5 s scanner timeout
    return "slow"


if __name__ == "__main__":
    lab.run(host="127.0.0.1", port=5001, debug=False, threaded=True)
