#!/usr/bin/env python3
"""
report_generator.py - Creates JSON and HTML reports from scan results.

The scanner (scanner.py) produces a Python dictionary. This file turns
that dictionary into:
  * a JSON file  (good for other programs to read)
  * an HTML file (good for humans to read in a browser)

You can also convert an old JSON report to HTML:
    python report_generator.py reports\\scan_xxx.json reports\\new_report.html
"""

import html
import json
import os
import sys

# Colours used for the status badges in the HTML report.
STATUS_COLOURS = {
    "PASS": "#2e7d32",
    "MISSING": "#ef6c00",
    "WEAK": "#f9a825",
    "CONFIRMED": "#c62828",
    "INFO": "#1565c0",
    "N/A": "#757575",
}

STATUS_ORDER = ["PASS", "MISSING", "WEAK", "CONFIRMED", "INFO", "N/A"]

RATING_COLOURS = {
    "HIGH": "#c62828",
    "MEDIUM": "#ef6c00",
    "LOW": "#f9a825",
    "GOOD": "#2e7d32",
}

CSS = """
body { font-family: Segoe UI, Arial, sans-serif; margin: 0; background: #f4f6f8; color: #222; }
header { background: #1a237e; color: #fff; padding: 20px 32px; }
header h1 { margin: 0 0 6px 0; font-size: 24px; }
main { max-width: 960px; margin: 0 auto; padding: 24px 16px 48px 16px; }
.card { background: #fff; border-radius: 8px; padding: 16px 20px; margin-bottom: 18px;
        box-shadow: 0 1px 3px rgba(0,0,0,.15); }
table.meta td { padding: 3px 12px 3px 0; vertical-align: top; }
table.meta td:first-child { font-weight: 600; white-space: nowrap; }
.counts { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 8px; }
.count { color: #fff; border-radius: 6px; padding: 8px 14px; font-weight: 600; }
.badge { color: #fff; border-radius: 4px; padding: 2px 8px; font-size: 12px; font-weight: 700; }
.finding h3 { margin: 0 0 6px 0; font-size: 17px; }
.finding p { margin: 6px 0; }
.label { font-weight: 600; }
.classification { font-style: italic; color: #555; }
code, .evidence { font-family: Consolas, monospace; background: #eceff1; padding: 2px 5px;
                  border-radius: 3px; word-break: break-all; }
.error { background: #ffebee; border-left: 5px solid #c62828; }
.note { background: #fffde7; border-left: 5px solid #f9a825; }
footer { text-align: center; color: #666; font-size: 12px; padding: 12px; }
"""


def _e(value):
    """Escape text so it is safe to place inside HTML.
    This stops header values or error text from being run as code."""
    return html.escape(str(value), quote=True)


def _badge(status):
    colour = STATUS_COLOURS.get(status, "#555")
    return '<span class="badge" style="background:%s">%s</span>' % (
        colour, _e(status))


def _finding_html(finding):
    """Build the HTML block for a single finding."""
    parts = ['<div class="card finding">']
    parts.append("<h3>%s %s</h3>" % (_badge(finding.get("status", "")),
                                     _e(finding.get("name", ""))))
    parts.append('<p class="classification">%s &mdash; severity: %s</p>' % (
        _e(finding.get("classification", "")), _e(finding.get("severity", ""))))
    parts.append("<p>%s</p>" % _e(finding.get("summary", "")))
    if finding.get("why_it_matters"):
        parts.append('<p><span class="label">Why it matters:</span> %s</p>'
                     % _e(finding["why_it_matters"]))
    if finding.get("recommendation"):
        parts.append('<p><span class="label">Recommendation:</span> %s</p>'
                     % _e(finding["recommendation"]))
    if finding.get("evidence"):
        parts.append('<p><span class="label">Evidence:</span> '
                     '<span class="evidence">%s</span></p>'
                     % _e(finding["evidence"]))
    parts.append("</div>")
    return "\n".join(parts)


def build_html_report(result):
    """Return the complete HTML page (as a string) for one scan result."""
    summary = result.get("summary", {})
    counts = summary.get("counts", {})
    rating = summary.get("overall_rating", "GOOD")
    findings = result.get("findings", [])

    out = []
    out.append("<!DOCTYPE html>")
    out.append('<html lang="en"><head><meta charset="utf-8">')
    out.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    out.append("<title>Security Header Scan Report</title>")
    out.append("<style>%s</style></head><body>" % CSS)
    out.append("<header><h1>Web Security Header Scan Report</h1>")
    out.append("<div>%s v%s</div></header><main>" % (
        _e(result.get("tool", "")), _e(result.get("version", ""))))

    # Scan details
    out.append('<div class="card"><table class="meta">')
    for label, key in (("Target", "target"), ("Final URL", "final_url"),
                       ("HTTP status", "status_code"),
                       ("Scan time (UTC)", "scan_time_utc"),
                       ("Requests sent", "request_count")):
        out.append("<tr><td>%s</td><td>%s</td></tr>" % (
            _e(label), _e(result.get(key))))
    out.append("<tr><td>Overall rating</td><td>"
               '<span class="badge" style="background:%s">%s</span> '
               "(a simple guide, not a professional audit)</td></tr>" % (
                   RATING_COLOURS.get(rating, "#555"), _e(rating)))
    out.append("</table>")
    out.append('<div class="counts">')
    for status in STATUS_ORDER:
        out.append('<div class="count" style="background:%s">%s: %d</div>' % (
            STATUS_COLOURS[status], _e(status), counts.get(status, 0)))
    out.append("</div></div>")

    # Explanation of the difference between the statuses
    out.append('<div class="card note"><span class="label">How to read this '
               "report:</span> <b>MISSING</b> and <b>WEAK</b> mean a "
               "protection is absent or poorly set &mdash; these are "
               "hardening gaps, <b>not</b> confirmed vulnerabilities. "
               "<b>CONFIRMED</b> means the server's response showed clearly "
               "insecure behaviour. Nothing was exploited; real impact "
               "depends on what data the site holds.</div>")

    if result.get("error"):
        out.append('<div class="card error"><b>Scan error:</b> %s</div>'
                   % _e(result["error"]))

    # Findings grouped by category
    sections = (("header", "Security Headers"), ("cors", "CORS Checks"),
                ("general", "General Notes"))
    for category, title in sections:
        group = [f for f in findings if f.get("category") == category]
        if group:
            out.append("<h2>%s</h2>" % _e(title))
            for finding in group:
                out.append(_finding_html(finding))

    out.append("</main><footer>Generated by %s. Use only on systems you own "
               "or have permission to test.</footer></body></html>"
               % _e(result.get("tool", "")))
    return "\n".join(out)


def save_json_report(result, output_dir, filename):
    """Save the result as a JSON file and return its path."""
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    return path


def save_html_report(result, output_dir, filename):
    """Save the result as an HTML file and return its path."""
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(build_html_report(result))
    return path


def main(argv=None):
    """Convert an existing JSON report into an HTML report."""
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        print("Usage: python report_generator.py input.json output.html")
        return 1
    try:
        with open(argv[0], "r", encoding="utf-8") as handle:
            result = json.load(handle)
    except (OSError, json.JSONDecodeError) as err:
        print("Could not read the JSON file: %s" % err)
        return 1
    folder, name = os.path.split(argv[1])
    path = save_html_report(result, folder or ".", name)
    print("HTML report saved: %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
