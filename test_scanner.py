"""
Automated tests for the Web Security Header Scanner.

Run from the project folder with:
    python -m unittest discover -s tests -v

The tests start the local mock server on a random free port, so they
never touch the internet or any real website.
"""

import contextlib
import io
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from unittest import mock

# Allow "import scanner" when the tests run from any folder.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import mock_server          # noqa: E402
import report_generator     # noqa: E402
import scanner              # noqa: E402

# A complete set of good headers (as a plain dictionary).
GOOD_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=()",
}


def statuses(findings):
    """Turn a list of findings into {name: status} for easy checking."""
    return {f["name"]: f["status"] for f in findings}


# ---------------------------------------------------------------------------
# 1. Header checks (no network needed)
# ---------------------------------------------------------------------------
class TestHeaderChecks(unittest.TestCase):

    def test_all_headers_present_gives_pass(self):
        result = statuses(scanner.check_security_headers(GOOD_HEADERS, True))
        self.assertTrue(all(s == "PASS" for s in result.values()), result)

    def test_missing_headers_detected(self):
        result = statuses(scanner.check_security_headers({}, True))
        for name in ("Content-Security-Policy", "Strict-Transport-Security",
                     "X-Content-Type-Options", "X-Frame-Options",
                     "Referrer-Policy"):
            self.assertEqual(result[name], "MISSING", name)

    def test_missing_is_not_called_confirmed(self):
        for finding in scanner.check_security_headers({}, True):
            self.assertNotEqual(finding["status"], "CONFIRMED")
            self.assertIn("NOT a confirmed vulnerability",
                          finding["classification"])

    def test_header_names_are_case_insensitive(self):
        import requests
        headers = requests.structures.CaseInsensitiveDict(
            {"x-content-type-options": "nosniff"})
        finding = scanner.check_content_type_options(headers)
        self.assertEqual(finding["status"], "PASS")

    def test_hsts_not_applicable_over_http(self):
        finding = scanner.check_hsts({}, is_https=False)
        self.assertEqual(finding["status"], "N/A")

    def test_weak_hsts_short_max_age(self):
        finding = scanner.check_hsts(
            {"Strict-Transport-Security": "max-age=300"}, True)
        self.assertEqual(finding["status"], "WEAK")

    def test_hsts_without_max_age_is_weak(self):
        finding = scanner.check_hsts(
            {"Strict-Transport-Security": "includeSubDomains"}, True)
        self.assertEqual(finding["status"], "WEAK")

    def test_weak_csp_unsafe_inline(self):
        finding = scanner.check_csp(
            {"Content-Security-Policy": "script-src 'self' 'unsafe-inline'"})
        self.assertEqual(finding["status"], "WEAK")

    def test_weak_csp_wildcard_default(self):
        finding = scanner.check_csp(
            {"Content-Security-Policy": "default-src *"})
        self.assertEqual(finding["status"], "WEAK")

    def test_csp_without_script_restrictions_is_weak(self):
        finding = scanner.check_csp(
            {"Content-Security-Policy": "img-src 'self'"})
        self.assertEqual(finding["status"], "WEAK")

    def test_weak_content_type_options(self):
        finding = scanner.check_content_type_options(
            {"X-Content-Type-Options": "sniff"})
        self.assertEqual(finding["status"], "WEAK")

    def test_frame_protection_via_csp_frame_ancestors(self):
        finding = scanner.check_frame_protection(
            {"Content-Security-Policy": "frame-ancestors 'none'"})
        self.assertEqual(finding["status"], "PASS")

    def test_weak_x_frame_options(self):
        finding = scanner.check_frame_protection(
            {"X-Frame-Options": "ALLOW-FROM https://a.example"})
        self.assertEqual(finding["status"], "WEAK")

    def test_weak_referrer_policy(self):
        finding = scanner.check_referrer_policy(
            {"Referrer-Policy": "unsafe-url"})
        self.assertEqual(finding["status"], "WEAK")

    def test_information_leak_headers(self):
        findings = scanner.check_information_leaks(
            {"X-Powered-By": "PHP/5.6", "Server": "Apache/2.4.1"})
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f["status"] == "INFO" for f in findings))

    def test_server_header_without_version_is_ignored(self):
        self.assertEqual(
            scanner.check_information_leaks({"Server": "MockServer"}), [])


# ---------------------------------------------------------------------------
# 2. CORS analysis (no network needed)
# ---------------------------------------------------------------------------
class TestCorsAnalysis(unittest.TestCase):
    ORIGIN = scanner.TEST_ORIGIN

    def status_of(self, headers, origin=None):
        return scanner.analyze_cors(headers, origin or self.ORIGIN)[0]

    def test_no_cors_headers_is_pass(self):
        self.assertEqual(self.status_of({}), "PASS")

    def test_wildcard_is_info(self):
        self.assertEqual(
            self.status_of({"Access-Control-Allow-Origin": "*"}), "INFO")

    def test_wildcard_with_credentials_is_weak(self):
        headers = {"Access-Control-Allow-Origin": "*",
                   "Access-Control-Allow-Credentials": "true"}
        self.assertEqual(self.status_of(headers), "WEAK")

    def test_reflected_origin_with_credentials_is_confirmed(self):
        headers = {"Access-Control-Allow-Origin": self.ORIGIN,
                   "Access-Control-Allow-Credentials": "true"}
        self.assertEqual(self.status_of(headers), "CONFIRMED")

    def test_reflected_origin_without_credentials_is_weak(self):
        headers = {"Access-Control-Allow-Origin": self.ORIGIN}
        self.assertEqual(self.status_of(headers), "WEAK")

    def test_null_origin_with_credentials_is_confirmed(self):
        headers = {"Access-Control-Allow-Origin": "null",
                   "Access-Control-Allow-Credentials": "true"}
        self.assertEqual(self.status_of(headers, "null"), "CONFIRMED")

    def test_specific_trusted_origin_is_pass(self):
        headers = {"Access-Control-Allow-Origin": "https://trusted.example"}
        self.assertEqual(self.status_of(headers), "PASS")


# ---------------------------------------------------------------------------
# 3. URL validation and safety rules
# ---------------------------------------------------------------------------
class TestUrlSafety(unittest.TestCase):

    def test_adds_https_when_scheme_missing(self):
        self.assertEqual(scanner.normalize_url("example.com"),
                         "https://example.com")

    def test_rejects_empty_url(self):
        with self.assertRaises(scanner.ScanError):
            scanner.normalize_url("   ")

    def test_rejects_non_http_scheme(self):
        with self.assertRaises(scanner.ScanError):
            scanner.normalize_url("ftp://example.com")

    def test_rejects_url_with_spaces(self):
        with self.assertRaises(scanner.ScanError):
            scanner.normalize_url("http://exa mple.com")

    def test_rejects_bad_port(self):
        with self.assertRaises(scanner.ScanError):
            scanner.normalize_url("http://example.com:99999")

    def test_rejects_missing_host(self):
        with self.assertRaises(scanner.ScanError):
            scanner.normalize_url("http://")

    def test_private_address_always_blocked(self):
        with mock.patch("scanner.resolve_host", return_value=["192.168.1.5"]):
            with self.assertRaises(scanner.ScanError) as ctx:
                scanner.check_target_allowed("http://intranet.test/", True, True)
        self.assertIn("private", str(ctx.exception))

    def test_link_local_address_blocked(self):
        with mock.patch("scanner.resolve_host", return_value=["169.254.169.254"]):
            with self.assertRaises(scanner.ScanError):
                scanner.check_target_allowed("http://metadata.test/", True, True)

    def test_loopback_blocked_without_allow_local(self):
        with self.assertRaises(scanner.ScanError):
            scanner.check_target_allowed("http://127.0.0.1:8000/", False, False)

    def test_loopback_allowed_with_allow_local(self):
        scanner.check_target_allowed("http://127.0.0.1:8000/", True, False)

    def test_public_site_needs_permission_flag(self):
        with mock.patch("scanner.resolve_host", return_value=["93.184.216.34"]):
            with self.assertRaises(scanner.ScanError) as ctx:
                scanner.check_target_allowed("https://site.test/", False, False)
            self.assertIn("permission", str(ctx.exception))
            # With the flag it is allowed (no exception).
            scanner.check_target_allowed("https://site.test/", False, True)


# ---------------------------------------------------------------------------
# 4. Full scans against the local mock server
# ---------------------------------------------------------------------------
class TestScanMockServer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = mock_server.create_server(port=0, quiet=True)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:%d" % cls.port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def scan(self, path, **kwargs):
        kwargs.setdefault("allow_local", True)
        kwargs.setdefault("delay", 0)
        kwargs.setdefault("timeout", 5)
        return scanner.run_scan(self.base + path, **kwargs)

    def test_secure_page_has_no_missing_headers(self):
        result = self.scan("/secure")
        self.assertIsNone(result["error"])
        found = statuses(result["findings"])
        self.assertEqual(found["Content-Security-Policy"], "PASS")
        self.assertEqual(found["X-Content-Type-Options"], "PASS")
        self.assertEqual(found["X-Frame-Options"], "PASS")
        self.assertEqual(found["Referrer-Policy"], "PASS")
        self.assertEqual(found["Strict-Transport-Security"], "N/A")
        self.assertEqual(result["summary"]["counts"]["MISSING"], 0)
        self.assertEqual(result["summary"]["overall_rating"], "GOOD")

    def test_insecure_page_has_missing_headers(self):
        result = self.scan("/insecure")
        found = statuses(result["findings"])
        for name in ("Content-Security-Policy", "X-Content-Type-Options",
                     "X-Frame-Options", "Referrer-Policy"):
            self.assertEqual(found[name], "MISSING", name)
        self.assertEqual(found["X-Powered-By"], "INFO")
        self.assertEqual(result["summary"]["counts"]["CONFIRMED"], 0)
        self.assertEqual(result["summary"]["overall_rating"], "MEDIUM")

    def test_weak_page_has_weak_headers(self):
        found = statuses(self.scan("/weak")["findings"])
        for name in ("Content-Security-Policy", "X-Content-Type-Options",
                     "X-Frame-Options", "Referrer-Policy"):
            self.assertEqual(found[name], "WEAK", name)

    def test_cors_reflect_is_confirmed(self):
        result = self.scan("/cors-reflect")
        found = statuses(result["findings"])
        self.assertEqual(found["CORS - arbitrary origin"], "CONFIRMED")
        self.assertEqual(found["CORS - preflight (OPTIONS)"], "CONFIRMED")
        self.assertEqual(result["summary"]["overall_rating"], "HIGH")

    def test_cors_reflect_without_credentials_is_weak(self):
        found = statuses(self.scan("/cors-reflect-nocreds")["findings"])
        self.assertEqual(found["CORS - arbitrary origin"], "WEAK")

    def test_cors_wildcard_is_info(self):
        found = statuses(self.scan("/cors-wildcard")["findings"])
        self.assertEqual(found["CORS - arbitrary origin"], "INFO")

    def test_cors_null_is_confirmed(self):
        found = statuses(self.scan("/cors-null")["findings"])
        self.assertEqual(found["CORS - null origin"], "CONFIRMED")
        self.assertEqual(found["CORS - arbitrary origin"], "PASS")

    def test_cors_safe_is_pass(self):
        found = statuses(self.scan("/cors-safe")["findings"])
        self.assertEqual(found["CORS - arbitrary origin"], "PASS")
        self.assertEqual(found["CORS - null origin"], "PASS")

    def test_redirect_is_followed(self):
        result = self.scan("/redirect")
        self.assertIsNone(result["error"])
        self.assertTrue(result["final_url"].endswith("/secure"))

    def test_http_404_is_reported_safely(self):
        result = self.scan("/does-not-exist")
        self.assertIsNone(result["error"])
        self.assertEqual(result["status_code"], 404)
        self.assertEqual(result["findings"][0]["name"], "HTTP status")

    def test_request_count_is_small(self):
        result = self.scan("/secure")
        self.assertLessEqual(result["request_count"], 4)

    def test_timeout_is_handled(self):
        result = self.scan("/slow", timeout=1)
        self.assertIsNotNone(result["error"])
        self.assertIn("timed out", result["error"])

    def test_connection_refused_is_handled(self):
        # Find a port that nothing is listening on.
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        free_port = sock.getsockname()[1]
        sock.close()
        result = scanner.run_scan("http://127.0.0.1:%d/" % free_port,
                                  allow_local=True, delay=0, timeout=2)
        self.assertIn("Could not connect", result["error"])

    def test_localhost_blocked_without_flag(self):
        result = self.scan("/secure", allow_local=False)
        self.assertIn("Blocked", result["error"])
        self.assertEqual(result["request_count"], 0)

    def test_invalid_url_is_handled(self):
        result = scanner.run_scan("ftp://example.com", delay=0)
        self.assertIn("http", result["error"])

    def test_command_line_creates_reports(self):
        with tempfile.TemporaryDirectory() as folder:
            with contextlib.redirect_stdout(io.StringIO()):
                code = scanner.main([self.base + "/demo", "--allow-local",
                                     "--output-dir", folder])
            self.assertEqual(code, 0)
            files = os.listdir(folder)
            self.assertEqual(len([f for f in files if f.endswith(".json")]), 1)
            self.assertEqual(len([f for f in files if f.endswith(".html")]), 1)

    def test_command_line_returns_error_code_when_blocked(self):
        with tempfile.TemporaryDirectory() as folder:
            with contextlib.redirect_stdout(io.StringIO()):
                code = scanner.main([self.base + "/demo",
                                     "--output-dir", folder])
            self.assertEqual(code, 1)
            self.assertEqual(os.listdir(folder), [])


# ---------------------------------------------------------------------------
# 5. Report generation
# ---------------------------------------------------------------------------
class TestReports(unittest.TestCase):

    def sample_result(self):
        findings = scanner.check_security_headers({}, True)
        return {"tool": "T", "version": "1", "target": "http://x.test",
                "final_url": "http://x.test", "scan_time_utc": "now",
                "status_code": 200, "request_count": 1, "error": None,
                "findings": findings, "summary": scanner.summarize(findings)}

    def test_html_contains_key_sections(self):
        page = report_generator.build_html_report(self.sample_result())
        self.assertIn("Content-Security-Policy", page)
        self.assertIn("Why it matters", page)
        self.assertIn("Recommendation", page)
        self.assertIn("NOT a confirmed vulnerability", page)

    def test_html_escapes_dangerous_text(self):
        result = self.sample_result()
        result["findings"][0]["evidence"] = "<script>alert(1)</script>"
        page = report_generator.build_html_report(result)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_json_report_is_valid_json(self):
        with tempfile.TemporaryDirectory() as folder:
            path = report_generator.save_json_report(
                self.sample_result(), folder, "r.json")
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
            self.assertEqual(data["target"], "http://x.test")

    def test_json_can_be_converted_to_html(self):
        with tempfile.TemporaryDirectory() as folder:
            json_path = report_generator.save_json_report(
                self.sample_result(), folder, "r.json")
            html_path = os.path.join(folder, "r.html")
            with contextlib.redirect_stdout(io.StringIO()):
                code = report_generator.main([json_path, html_path])
            self.assertEqual(code, 0)
            self.assertTrue(os.path.getsize(html_path) > 500)

    def test_converter_handles_missing_file(self):
        with contextlib.redirect_stdout(io.StringIO()):
            code = report_generator.main(["does_not_exist.json", "out.html"])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
