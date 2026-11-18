"""Flask web app: dashboard, new scan, results, history, report export."""
from flask import Flask, Response, abort, flash, redirect, render_template, request, url_for

import config
import database as db
import reports
from scanner.engine import run_scan
from scanner.policy import TargetRejected, validate_url
from scanner.severity import SEVERITY_ORDER

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
db.init_db()


@app.context_processor
def inject_globals():
    return {"SEVERITY_ORDER": SEVERITY_ORDER, "LIMITATIONS": config.LIMITATIONS, "SCOPE_TEXT": config.SCOPE_TEXT}


@app.route("/")
def dashboard():
    return render_template("dashboard.html", **db.dashboard_stats())


@app.route("/scan/new", methods=["GET", "POST"])
def new_scan():
    url = ""
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not request.form.get("authorized"):
            flash("You must confirm that you are authorized to scan this target.", "error")
            return render_template("new_scan.html", url=url, allowed=sorted(config.ALLOWED_HOSTS))
        try:
            url = validate_url(url)               # rejected BEFORE any request or DB record
        except TargetRejected as e:
            flash(f"Target rejected: {e}", "error")
            return render_template("new_scan.html", url=url, allowed=sorted(config.ALLOWED_HOSTS))
        scan_id = db.create_scan(url)
        try:
            findings, status, err = run_scan(url)
        except Exception as e:                    # keep the app alive on any unexpected failure
            findings, status, err = [], "Failed", f"{type(e).__name__}: {e}"
        db.finish_scan(scan_id, status, findings, err)
        return redirect(url_for("scan_result", scan_id=scan_id))
    return render_template("new_scan.html", url=url, allowed=sorted(config.ALLOWED_HOSTS))


@app.route("/scan/<int:scan_id>")
def scan_result(scan_id):
    scan = db.get_scan(scan_id) or abort(404)
    return render_template("result.html", scan=scan, findings=db.get_findings(scan_id),
                           counts=db.severity_counts(scan_id))


@app.route("/scan/<int:scan_id>/finding/<int:finding_id>")
def finding_detail(scan_id, finding_id):
    scan = db.get_scan(scan_id) or abort(404)
    finding = db.get_finding(scan_id, finding_id) or abort(404)
    return render_template("finding.html", scan=scan, f=finding)


@app.route("/history")
def history():
    return render_template("history.html", scans=db.list_scans())


@app.route("/scan/<int:scan_id>/export.csv")
def export_csv(scan_id):
    scan = db.get_scan(scan_id) or abort(404)
    data = reports.csv_report(scan, db.get_findings(scan_id))
    return Response(data, mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.csv"})


@app.route("/scan/<int:scan_id>/export.pdf")
def export_pdf(scan_id):
    scan = db.get_scan(scan_id) or abort(404)
    try:
        data = reports.pdf_report(scan, db.get_findings(scan_id))
    except Exception as e:
        flash(f"PDF export failed ({e}). Use the CSV export instead.", "error")
        return redirect(url_for("scan_result", scan_id=scan_id))
    return Response(data, mimetype="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.pdf"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
