"""CSV and PDF report generation."""
import csv
import io
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

import config
import database as db


def csv_report(scan, findings):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["scan_id", "target_url", "started_at", "completed_at", "scan_status", "risk_summary"])
    w.writerow([scan["id"], scan["target_url"], scan["started_at"], scan["completed_at"], scan["status"], scan["risk_summary"]])
    w.writerow([])
    w.writerow(["check_name", "category", "title", "status", "severity", "evidence", "explanation", "recommendation", "rule_reason"])
    for f in findings:
        w.writerow([f["check_name"], f["category"], f["title"], f["status"], f["severity"], f["evidence"],
                    f["explanation"], f["recommendation"], f["rule_reason"]])
    return buf.getvalue()


def pdf_report(scan, findings):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm)
    ss = getSampleStyleSheet()
    P = lambda t, s="BodyText": Paragraph(escape(str(t)), ss[s])
    story = [P("Automated Vulnerability Scanner - Scan Report", "Title"),
             P("ET 401 Learning Technologies Project Course", "Heading4"), Spacer(1, 6)]

    details = [["Scan ID", scan["id"]], ["Target", scan["target_url"]], ["Started", scan["started_at"]],
               ["Completed", scan["completed_at"]], ["Status", scan["status"]],
               ["Rule-based risk summary", f'{scan["risk_summary"]} (not a CVSS score)']]
    t = Table([[P(a), P(b)] for a, b in details], colWidths=[50 * mm, 120 * mm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [t, Spacer(1, 8), P("Authorized scope", "Heading3"), P(config.SCOPE_TEXT)]

    counts = db.severity_counts(scan["id"])
    story += [P("Severity summary", "Heading3"), P(" | ".join(f"{k}: {v}" for k, v in counts.items()))]

    story.append(P("Checks performed", "Heading3"))
    for name in sorted({f["check_name"] for f in findings}):
        story.append(P(f"- {name}"))

    story.append(P("Findings", "Heading3"))
    for f in findings:
        block = [P(f'[{f["severity"]}] {f["title"]}  ({f["status"]})', "Heading4"),
                 P(f'Evidence: {f["evidence"]}'), P(f'Explanation: {f["explanation"]}'),
                 P(f'Remediation: {f["recommendation"]}'), P(f'Severity rule: {f["rule_reason"]}'), Spacer(1, 6)]
        story += block

    story.append(P("Limitations", "Heading3"))
    for l in config.LIMITATIONS:
        story.append(P(f"- {l}"))
    doc.build(story)
    return buf.getvalue()
