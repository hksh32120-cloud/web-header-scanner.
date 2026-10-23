#!/usr/bin/env python3
"""
scanner.py - Automated Web Security Header Scanner
===================================================

What this program does
----------------------
1. Takes a website URL from the command line.
2. Sends ONE normal GET request and reads the HTTP *response headers*.
3. Checks the important security headers (CSP, HSTS, X-Content-Type-Options,
   X-Frame-Options, Referrer-Policy, Permissions-Policy).
4. Sends up to THREE harmless extra requests to check CORS settings
   (an "Origin" header from a fake site, the "null" origin, and one
   OPTIONS preflight request).
5. Writes a JSON report and an HTML report.

Safety rules built into the program
-----------------------------------
* It only READS headers. It never exploits anything, logs in, or
  sends attack payloads.
* It refuses private-network addresses (192.168.x.x, 10.x.x.x, etc.).
* It refuses real websites unless you add --i-have-permission.
* Localhost (your own laptop) is allowed only with --allow-local.
* It uses a timeout, a small delay between requests, and a hard limit
  on the number of redirects, so it never floods a server.

IMPORTANT: Only scan websites that you own or have written permission
to test. Scanning other people's websites may be illegal.
"""

import argparse
import ipaddress
import json
import re
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests

import report_generator

# ---------------------------------------------------------------------------
# Settings (constants)
# ---------------------------------------------------------------------------
TOOL_NAME = "Automated Web Security Header Scanner"
TOOL_VERSION = "1.0.0"
DEFAULT_TIMEOUT = 8          # seconds to wait for a server reply
MAX_REDIRECTS = 3            # never follow more than 3 redirects
REQUEST_DELAY = 0.5          # pause (seconds) between requests
USER_AGENT = "WebSecurityHeaderScanner/%s (educational project)" % TOOL_VERSION
# A fake website name used to test CORS. ".example" is reserved by the
# internet standards, so this name can never belong to a real site.
TEST_ORIGIN = "https://untrusted-origin.example"
REDIRECT_CODES = (301, 302, 303, 307, 308)

# Possible results for each check ("status").
STATUS_PASS = "PASS"
STATUS_MISSING = "MISSING"
STATUS_WEAK = "WEAK"
STATUS_CONFIRMED = "CONFIRMED"
STATUS_INFO = "INFO"
STATUS_NA = "N/A"
ALL_STATUSES = (STATUS_PASS, STATUS_MISSING, STATUS_WEAK,
                STATUS_CONFIRMED, STATUS_INFO, STATUS_NA)

# What each status means. This is how the tool separates a simple
# "missing header" from a "confirmed" problem.
CLASSIFICATION = {
    STATUS_PASS: "Good - secure setting observed",
    STATUS_MISSING: "Missing header - hardening gap, NOT a confirmed vulnerability",
    STATUS_WEAK: "Weak setting - hardening gap, NOT a confirmed vulnerability",
    STATUS_CONFIRMED: ("Confirmed misconfiguration - insecure behaviour was "
                       "observed in the server's response (not exploited)"),
    STATUS_INFO: "Informational - please review manually",
    STATUS_NA: "Not applicable to this target",
}

# Explanations shown in the report for every header we check.
HEADER_KNOWLEDGE = {
    "Content-Security-Policy": {
        "severity": "medium",
        "why": ("CSP tells the browser which scripts, images and frames a page "
                "may load. It is the strongest defence against Cross-Site "
                "Scripting (XSS) and data injection."),
        "fix": ("Add a policy such as: Content-Security-Policy: default-src "
                "'self'; script-src 'self'; frame-ancestors 'none'. Avoid "
                "'unsafe-inline', 'unsafe-eval' and the * wildcard."),
    },
    "Strict-Transport-Security": {
        "severity": "medium",
        "why": ("HSTS forces browsers to use HTTPS only. Without it, an "
                "attacker on the same network can downgrade the connection "
                "to plain HTTP (SSL-stripping)."),
        "fix": ("Add: Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains (only on HTTPS sites)."),
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "why": ("Stops browsers from guessing ('sniffing') file types. "
                "Sniffing can turn an uploaded text file into running "
                "JavaScript."),
        "fix": "Add: X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "why": ("Controls whether other sites can show your page inside a "
                "frame. Without it, your site may be vulnerable to "
                "clickjacking (users tricked into clicking hidden buttons)."),
        "fix": ("Add: X-Frame-Options: DENY (or SAMEORIGIN), or use the CSP "
                "directive frame-ancestors."),
    },
    "Referrer-Policy": {
        "severity": "low",
        "why": ("Controls how much of the page address is sent to other "
                "sites when a user clicks a link. Full URLs may contain "
                "private tokens or IDs."),
        "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "low",
        "why": ("Lets a site switch off powerful browser features (camera, "
                "microphone, location) that it does not need, limiting "
                "damage if a script is compromised."),
        "fix": "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
    },
}

CORS_WHY = ("CORS decides which OTHER websites may read this site's responses "
            "from a browser. A rule that is too loose could let a malicious "
            "website read data that should stay private.")
CORS_FIX = ("Allow only a fixed list of trusted origins. Never copy the "
            "Origin header back blindly, never trust the 'null' origin, do "
            "not combine * with credentials, and add 'Vary: Origin'.")


class ScanError(Exception):
    """Raised for any problem we want to show to the user in plain English."""


# ---------------------------------------------------------------------------
# Part 1: URL validation and safety checks
# ---------------------------------------------------------------------------
def normalize_url(raw_url):
    """Clean the URL typed by the user and make sure it is usable."""
    raw_url = (raw_url or "").strip()
    if not raw_url:
        raise ScanError("The URL is empty. Example: https://example.com")
    if re.search(r"\s", raw_url):
        raise ScanError("The URL must not contain spaces.")
    if "://" not in raw_url:
        raw_url = "https://" + raw_url      # default to HTTPS
    parsed = urlparse(raw_url)
    if parsed.scheme not in ("http", "https"):
        raise ScanError("Only http:// and https:// URLs are supported.")
    if not parsed.hostname:
        raise ScanError("The URL has no website name (host).")
    try:
        _ = parsed.port                      # raises ValueError if bad port
    except ValueError:
        raise ScanError("The port number in the URL is invalid.")
    return raw_url


def resolve_host(hostname):
    """Look up the IP address(es) of a host name."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise ScanError("Could not find the website '%s'. Check the spelling "
                        "and your internet connection." % hostname)
    return sorted({info[4][0] for info in infos})


def check_target_allowed(url, allow_local, permission_confirmed):
    """
    Decide whether we are allowed to send a request to this URL.
      * loopback (127.0.0.1 / localhost)  -> only with --allow-local
      * private / reserved networks       -> ALWAYS blocked
      * public internet                   -> only with --i-have-permission
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ScanError("Blocked: only http and https are allowed.")
    hostname = parsed.hostname
    if not hostname:
        raise ScanError("The URL has no website name (host).")

    for address in resolve_host(hostname):
        ip = ipaddress.ip_address(address.split("%")[0])
        if ip.version == 6 and ip.ipv4_mapped:      # e.g. ::ffff:127.0.0.1
            ip = ip.ipv4_mapped
        if ip.is_loopback:
            if not allow_local:
                raise ScanError(
                    "Blocked: '%s' is your own computer (localhost). To test "
                    "the local mock server, add --allow-local." % hostname)
        elif not ip.is_global:
            raise ScanError(
                "Blocked: '%s' points to a private or reserved network "
                "address (%s). This tool never scans private networks."
                % (hostname, ip))
        elif not permission_confirmed:
            raise ScanError(
                "Blocked: scanning a real website needs your confirmation. "
                "Only scan sites you own or have written permission to test, "
                "then add --i-have-permission.")


# ---------------------------------------------------------------------------
# Part 2: Sending requests safely
# ---------------------------------------------------------------------------
class Requester:
    """Sends HTTP requests with a timeout, a delay and a redirect limit."""

    def __init__(self, timeout, allow_local, permission_confirmed, delay):
        self.timeout = timeout
        self.allow_local = allow_local
        self.permission_confirmed = permission_confirmed
        self.delay = delay
        self.request_count = 0

    def send(self, url, method="GET", extra_headers=None,
             follow_redirects=True):
        """
        Send one request. Returns (response, final_url).
        Raises ScanError with a friendly message if anything goes wrong.
        """
        headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        headers.update(extra_headers or {})
        original_host = urlparse(url).hostname
        current_url = url
        hops_allowed = MAX_REDIRECTS if follow_redirects else 0

        for _ in range(hops_allowed + 1):
            # Safety check before EVERY request (also after redirects).
            check_target_allowed(current_url, self.allow_local,
                                 self.permission_confirmed)
            if self.request_count > 0 and self.delay > 0:
                time.sleep(self.delay)
            self.request_count += 1

            try:
                # stream=True means the page body is NOT downloaded;
                # we only need the headers.
                response = requests.request(
                    method, current_url, headers=headers,
                    timeout=self.timeout, allow_redirects=False, stream=True)
            except requests.exceptions.Timeout:
                raise ScanError("The request timed out after %s seconds."
                                % self.timeout)
            except requests.exceptions.SSLError:
                raise ScanError("HTTPS certificate problem. The site's "
                                "certificate could not be verified.")
            except requests.exceptions.ConnectionError:
                raise ScanError("Could not connect. The server may be down, "
                                "the port may be wrong, or it refused us.")
            except (requests.exceptions.InvalidURL,
                    requests.exceptions.MissingSchema,
                    requests.exceptions.InvalidSchema):
                raise ScanError("The URL is not valid.")
            except requests.exceptions.RequestException as err:
                raise ScanError("Request failed: %s" % err)
            response.close()

            location = response.headers.get("Location")
            if (follow_redirects and response.status_code in REDIRECT_CODES
                    and location):
                next_url = urljoin(current_url, location)
                if urlparse(next_url).hostname != original_host:
                    raise ScanError(
                        "The site redirects to a different host (%s). Scan "
                        "that host directly, if you have permission."
                        % urlparse(next_url).hostname)
                current_url = next_url
                continue
            return response, current_url

        raise ScanError("Too many redirects (limit is %d)." % MAX_REDIRECTS)


# ---------------------------------------------------------------------------
# Part 3: Building findings
# ---------------------------------------------------------------------------
def make_finding(category, name, status, severity, summary,
                 why="", recommendation="", evidence=""):
    """Create one finding (a plain dictionary, easy to save as JSON)."""
    if status in (STATUS_PASS, STATUS_NA):
        severity = "none"
    return {
        "category": category,
        "name": name,
        "status": status,
        "classification": CLASSIFICATION[status],
        "severity": severity,
        "summary": summary,
        "why_it_matters": why,
        "recommendation": recommendation,
        "evidence": evidence,
    }


def _missing(name):
    """Finding for a header that is not present."""
    info = HEADER_KNOWLEDGE[name]
    return make_finding("header", name, STATUS_MISSING, info["severity"],
                        "The %s header is missing." % name,
                        info["why"], info["fix"])


def _weak(name, problems, value):
    """Finding for a header that is present but configured badly."""
    info = HEADER_KNOWLEDGE[name]
    return make_finding("header", name, STATUS_WEAK, "low",
                        " ".join(problems), info["why"], info["fix"],
                        "%s: %s" % (name, value))


def _good(name, value, note=""):
    """Finding for a header that looks fine."""
    return make_finding("header", name, STATUS_PASS, "none",
                        ("Present and looks good. " + note).strip(),
                        evidence="%s: %s" % (name, value))


# ---------------------------------------------------------------------------
# Part 4: Security header checks
# ---------------------------------------------------------------------------
def find_csp_problems(value):
    """Return a list of weaknesses found inside a CSP header value."""
    directives = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]

    # If script-src is missing, browsers fall back to default-src.
    script_sources = directives.get("script-src", directives.get("default-src"))
    problems = []
    if script_sources is None:
        problems.append("Neither script-src nor default-src is set, so "
                        "scripts are not restricted.")
    else:
        if "'unsafe-inline'" in script_sources:
            problems.append("Allows 'unsafe-inline' scripts, which weakens "
                            "XSS protection.")
        if "'unsafe-eval'" in script_sources:
            problems.append("Allows 'unsafe-eval', which permits eval().")
        if "*" in script_sources:
            problems.append("Uses the * wildcard, so scripts may load from "
                            "any website.")
    return problems


def check_csp(headers):
    name = "Content-Security-Policy"
    value = headers.get(name)
    if value is None:
        return _missing(name)
    problems = find_csp_problems(value)
    if problems:
        return _weak(name, problems, value)
    return _good(name, value)


def check_hsts(headers, is_https):
    name = "Strict-Transport-Security"
    value = headers.get(name)
    if not is_https:
        # Browsers ignore HSTS sent over plain HTTP, so we cannot judge it.
        return make_finding(
            "header", name, STATUS_NA, "none",
            "The page was loaded over HTTP. HSTS only works on HTTPS, so "
            "this check does not apply.",
            evidence="Header present: %s" % ("yes" if value else "no"))
    if value is None:
        return _missing(name)
    match = re.search(r'max-age\s*=\s*"?(\d+)"?', value, re.IGNORECASE)
    if not match:
        return _weak(name, ["No valid max-age value was found."], value)
    max_age = int(match.group(1))
    if max_age < 15552000:      # 180 days
        return _weak(name, ["max-age is %d seconds; at least 15552000 "
                            "(180 days) is recommended, 31536000 is "
                            "better." % max_age], value)
    return _good(name, value)


def check_content_type_options(headers):
    name = "X-Content-Type-Options"
    value = headers.get(name)
    if value is None:
        return _missing(name)
    if value.strip().lower() != "nosniff":
        return _weak(name, ["The value should be exactly 'nosniff'."], value)
    return _good(name, value)


def check_frame_protection(headers):
    """X-Frame-Options, or the modern CSP 'frame-ancestors' alternative."""
    name = "X-Frame-Options"
    value = headers.get(name)
    csp = headers.get("Content-Security-Policy", "")
    has_frame_ancestors = "frame-ancestors" in csp.lower()

    if value is None:
        if has_frame_ancestors:
            return _good(name, "(not set)",
                         "Protection is provided by the CSP frame-ancestors "
                         "directive instead.")
        return _missing(name)
    if value.strip().upper() in ("DENY", "SAMEORIGIN"):
        return _good(name, value)
    return _weak(name, ["The value should be DENY or SAMEORIGIN "
                        "(ALLOW-FROM is obsolete)."], value)


def check_referrer_policy(headers):
    name = "Referrer-Policy"
    value = headers.get(name)
    if value is None:
        return _missing(name)
    # If several policies are listed, the browser uses the last one it knows.
    last = [t.strip().lower() for t in value.split(",")][-1]
    if last in ("unsafe-url", "no-referrer-when-downgrade", ""):
        return _weak(name, ["The policy '%s' can leak full page addresses "
                            "to other sites." % last], value)
    return _good(name, value)


def check_permissions_policy(headers):
    name = "Permissions-Policy"
    value = headers.get(name)
    if value is None:
        return _missing(name)
    return _good(name, value)


def check_information_leaks(headers):
    """Report headers that reveal software names/versions (informational)."""
    findings = []
    powered_by = headers.get("X-Powered-By")
    if powered_by:
        findings.append(make_finding(
            "header", "X-Powered-By", STATUS_INFO, "low",
            "The server reveals the technology it uses.",
            "Version details help attackers look up known bugs.",
            "Remove the X-Powered-By header.",
            "X-Powered-By: %s" % powered_by))
    server = headers.get("Server")
    if server and re.search(r"\d", server):
        findings.append(make_finding(
            "header", "Server", STATUS_INFO, "low",
            "The Server header reveals a version number.",
            "Version details help attackers look up known bugs.",
            "Hide the version in the web server configuration.",
            "Server: %s" % server))
    return findings


def check_security_headers(headers, is_https):
    """Run every header check and return a list of findings."""
    findings = [
        check_csp(headers),
        check_hsts(headers, is_https),
        check_content_type_options(headers),
        check_frame_protection(headers),
        check_referrer_policy(headers),
        check_permissions_policy(headers),
    ]
    findings.extend(check_information_leaks(headers))
    return findings


# ---------------------------------------------------------------------------
# Part 5: Basic, cautious CORS checks
# ---------------------------------------------------------------------------
def analyze_cors(headers, sent_origin):
    """
    Look at the CORS headers the server sent back.
    Returns (status, severity, summary).
    Only a clearly dangerous combination is called CONFIRMED.
    """
    acao = headers.get("Access-Control-Allow-Origin")
    credentials = (headers.get("Access-Control-Allow-Credentials") or ""
                   ).strip().lower() == "true"

    if acao is None:
        return (STATUS_PASS, "none",
                "No CORS permission was granted to this origin, so browsers "
                "will block cross-origin reads.")
    acao = acao.strip()

    if acao == "*":
        if credentials:
            return (STATUS_WEAK, "medium",
                    "Wildcard (*) is combined with Allow-Credentials: true. "
                    "Browsers reject this combination, so it is not directly "
                    "exploitable, but it shows a confused CORS setup.")
        return (STATUS_INFO, "low",
                "Wildcard (*): any website can read this response. This is "
                "fine for fully public data, but risky for private data.")

    if acao.lower() == "null":
        if credentials:
            return (STATUS_CONFIRMED, "high",
                    "The server trusts the 'null' origin AND allows "
                    "credentials. Sandboxed pages and local files can send "
                    "'null', so they could read logged-in responses.")
        return (STATUS_WEAK, "medium",
                "The server trusts the 'null' origin. Attackers can send "
                "this origin from sandboxed pages.")

    if acao == sent_origin:
        if credentials:
            return (STATUS_CONFIRMED, "high",
                    "The server copied our untrusted Origin back AND allows "
                    "credentials. Any website could read logged-in "
                    "responses from this server.")
        return (STATUS_WEAK, "medium",
                "The server copies any Origin back to us. Any website can "
                "read this response. Check that it holds no private data.")

    return (STATUS_PASS, "none",
            "Only a specific origin (%s) is allowed, not our untrusted "
            "test origin." % acao)


def run_cors_checks(requester, url):
    """Send up to 3 harmless requests and analyse the CORS answers."""
    probes = [
        ("CORS - arbitrary origin", "GET", TEST_ORIGIN),
        ("CORS - null origin", "GET", "null"),
        ("CORS - preflight (OPTIONS)", "OPTIONS", TEST_ORIGIN),
    ]
    findings = []
    for name, method, origin in probes:
        extra = {"Origin": origin}
        if method == "OPTIONS":
            extra["Access-Control-Request-Method"] = "GET"
        try:
            response, _ = requester.send(url, method, extra,
                                         follow_redirects=False)
        except ScanError as err:
            findings.append(make_finding(
                "cors", name, STATUS_INFO, "low",
                "This check could not be completed: %s" % err))
            continue

        status, severity, summary = analyze_cors(response.headers, origin)
        evidence = ("Origin sent: %s | Access-Control-Allow-Origin: %s | "
                    "Access-Control-Allow-Credentials: %s" % (
                        origin,
                        response.headers.get("Access-Control-Allow-Origin",
                                             "(not set)"),
                        response.headers.get("Access-Control-Allow-Credentials",
                                             "(not set)")))
        allow_methods = response.headers.get("Access-Control-Allow-Methods")
        if allow_methods:
            evidence += " | Allow-Methods: %s" % allow_methods
        findings.append(make_finding(
            "cors", name, status, severity, summary,
            CORS_WHY if status != STATUS_PASS else "",
            CORS_FIX if status != STATUS_PASS else "", evidence))
    return findings


# ---------------------------------------------------------------------------
# Part 6: Running a full scan
# ---------------------------------------------------------------------------
def summarize(findings):
    """Count findings per status and give a simple overall rating."""
    counts = {status: 0 for status in ALL_STATUSES}
    for finding in findings:
        counts[finding["status"]] += 1

    if counts[STATUS_CONFIRMED]:
        rating = "HIGH"
    elif any(f["status"] in (STATUS_MISSING, STATUS_WEAK)
             and f["severity"] in ("medium", "high") for f in findings):
        rating = "MEDIUM"
    elif counts[STATUS_MISSING] or counts[STATUS_WEAK]:
        rating = "LOW"
    else:
        rating = "GOOD"
    return {"counts": counts, "overall_rating": rating}


def run_scan(raw_url, timeout=DEFAULT_TIMEOUT, allow_local=False,
             permission_confirmed=False, delay=REQUEST_DELAY):
    """Scan one URL and return a result dictionary (never crashes)."""
    result = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "target": raw_url,
        "final_url": None,
        "scan_time_utc": datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"),
        "status_code": None,
        "request_count": 0,
        "error": None,
        "findings": [],
        "summary": summarize([]),
    }
    requester = None
    try:
        url = normalize_url(raw_url)
        result["target"] = url
        requester = Requester(timeout, allow_local, permission_confirmed,
                              delay)

        response, final_url = requester.send(url)
        result["final_url"] = final_url
        result["status_code"] = response.status_code

        findings = []
        if response.status_code >= 400:
            findings.append(make_finding(
                "general", "HTTP status", STATUS_INFO, "low",
                "The server answered with HTTP %d. Error pages sometimes "
                "carry different headers from normal pages, so scan a real "
                "page too." % response.status_code))
        is_https = urlparse(final_url).scheme == "https"
        findings.extend(check_security_headers(response.headers, is_https))
        findings.extend(run_cors_checks(requester, final_url))

        result["findings"] = findings
        result["summary"] = summarize(findings)
    except ScanError as err:
        result["error"] = str(err)
    finally:
        if requester is not None:
            result["request_count"] = requester.request_count
    return result


# ---------------------------------------------------------------------------
# Part 7: Command-line interface
# ---------------------------------------------------------------------------
def print_console_summary(result):
    """Print a short readable summary in the Command Prompt window."""
    print("")
    print("Target       : %s" % result["target"])
    print("Final URL    : %s" % result["final_url"])
    print("HTTP status  : %s" % result["status_code"])
    print("Requests sent: %s" % result["request_count"])
    print("-" * 70)
    for finding in result["findings"]:
        print("[%-9s] %s - %s" % (finding["status"], finding["name"],
                                  finding["summary"]))
        if finding["status"] in (STATUS_MISSING, STATUS_WEAK, STATUS_CONFIRMED):
            if finding["why_it_matters"]:
                print("              Why it matters: %s"
                      % finding["why_it_matters"])
            if finding["recommendation"]:
                print("              Fix: %s" % finding["recommendation"])
    print("-" * 70)
    counts = result["summary"]["counts"]
    print("Summary: " + ", ".join("%s=%d" % (s, counts[s])
                                  for s in ALL_STATUSES))
    print("Overall rating (simple guide): %s"
          % result["summary"]["overall_rating"])


def make_report_basename(result):
    """Create a Windows-safe file name like scan_127.0.0.1_8000_20260101_120000."""
    host = urlparse(result["target"]).netloc or "target"
    host = re.sub(r"[^A-Za-z0-9._-]", "_", host)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return "scan_%s_%s" % (host, stamp)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Audit a website's security headers and basic CORS "
                    "settings. Only scan sites you own or have permission "
                    "to test.")
    parser.add_argument("url", help="Target URL, e.g. http://127.0.0.1:8000/secure")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help="Seconds to wait for each response "
                             "(default %d)" % DEFAULT_TIMEOUT)
    parser.add_argument("--output-dir", default="reports",
                        help="Folder for the reports (default: reports)")
    parser.add_argument("--allow-local", action="store_true",
                        help="Allow scanning localhost (the mock server)")
    parser.add_argument("--i-have-permission", action="store_true",
                        help="Confirm you own the target or have written "
                             "permission to test it")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.timeout < 1 or args.timeout > 60:
        print("Error: --timeout must be between 1 and 60 seconds.")
        return 1

    print("%s v%s" % (TOOL_NAME, TOOL_VERSION))
    print("Reminder: only scan websites you own or may legally test.")

    result = run_scan(args.url, timeout=args.timeout,
                      allow_local=args.allow_local,
                      permission_confirmed=args.i_have_permission)

    if result["error"]:
        print("\nScan stopped: %s" % result["error"])
        return 1

    print_console_summary(result)

    try:
        base = make_report_basename(result)
        json_path = report_generator.save_json_report(
            result, args.output_dir, base + ".json")
        html_path = report_generator.save_html_report(
            result, args.output_dir, base + ".html")
    except OSError as err:
        print("\nCould not save the reports: %s" % err)
        return 1

    print("\nJSON report saved: %s" % json_path)
    print("HTML report saved: %s" % html_path)
    print("Open the HTML report on Windows with:  start \"\" \"%s\"" % html_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
