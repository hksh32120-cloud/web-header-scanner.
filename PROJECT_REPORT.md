# PROJECT REPORT

## Automated Web Security Header Scanner Using Python

| | |
|---|---|
| **Student name** | `<your name>` |
| **Roll / enrolment no.** | `<your number>` |
| **Course / semester** | B.Tech Computer Science, `<semester>` |
| **College / university** | `<your college>` |
| **Guide / supervisor** | `<guide name>` |
| **Academic year** | `<year>` |

*(Fill in the items in angle brackets. Everything else is a ready-to-edit draft. Rewrite sentences in your own words before submitting.)*

---

## 1. Abstract

Web servers send HTTP response headers that tell browsers how to behave securely. Missing or badly configured headers - such as Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options and Referrer-Policy - leave websites open to attacks such as cross-site scripting, clickjacking and protocol downgrade. Similarly, a loose Cross-Origin Resource Sharing (CORS) policy can allow a malicious website to read private data.

This project presents a Python command-line tool that audits a website for these weaknesses. It sends one normal request plus three harmless CORS probe requests, analyses the headers, separates *hardening gaps* (missing or weak headers) from *confirmed misconfigurations* (clearly insecure observed behaviour), and generates JSON and HTML reports with explanations and recommendations. Safety is built in: private networks are blocked, real websites require explicit confirmation, requests are rate-limited, and nothing is exploited. A local mock server with eleven test pages allows safe testing. The tool was verified with 56 automated tests.

**Keywords:** HTTP security headers, CORS, CSP, HSTS, Python, web security audit.

## 2. Problem Statement

Many websites are deployed without correct security headers because developers are unaware of them or configure them wrongly. Checking headers manually (browser developer tools) is slow and easy to get wrong, and many beginners cannot tell the difference between a *missing header* and a *real vulnerability*. There is a need for a simple, safe, automated tool that audits headers and basic CORS settings, explains each result in plain language, and does not harm or overload the target.

## 3. Objectives

1. Build a Python tool that accepts a URL from the command line and retrieves its HTTP response headers.
2. Check the presence and quality of five core security headers (plus Permissions-Policy).
3. Perform a cautious CORS configuration check using only harmless requests.
4. Classify results clearly as PASS, MISSING, WEAK, CONFIRMED, INFO or N/A, and avoid exaggerating missing headers as vulnerabilities.
5. Handle invalid URLs, timeouts, connection errors, certificate errors and HTTP errors without crashing.
6. Generate JSON and HTML reports with explanations and recommendations.
7. Provide a local mock server so the tool can be tested legally and safely.
8. Build in ethical safeguards (permission flag, private-network blocking, rate limiting).
9. Verify the tool with automated tests.

## 4. Existing System and Proposed System

### 4.1 Existing systems
- **Browser developer tools** - show headers one page at a time; no analysis or advice.
- **Online scanners** (e.g. public header-checking websites) - convenient but need internet, send your URL to a third party, cannot test local or private projects, and cannot be customised.
- **Professional tools** (e.g. OWASP ZAP, Burp Suite, Nikto) - powerful but complex, heavy for an 8 GB laptop, and active scanning features can be risky or illegal without permission.

### 4.2 Proposed system
A lightweight Python tool (one dependency) that:
- runs locally from the command line,
- performs only passive header reading plus three harmless CORS probes,
- explains *why* each finding matters and *how* to fix it,
- distinguishes hardening gaps from confirmed misconfigurations,
- includes a mock server for safe testing,
- produces JSON (for programs) and HTML (for humans) reports.

### 4.3 Comparison

| Feature | Browser tools | Online scanners | ZAP / Burp | Proposed tool |
|---|---|---|---|---|
| Automatic analysis | No | Yes | Yes | Yes |
| Works on local test server | Yes | No | Yes | Yes |
| Beginner friendly | Medium | Yes | No | Yes |
| Explains fixes | No | Some | Some | Yes |
| Built-in safety limits | n/a | n/a | Limited | Yes |
| Source code customisable | No | No | Limited | Yes |
| Resource use | Low | None (online) | High | Low |

## 5. System Requirements

### 5.1 Hardware
| Item | Minimum |
|---|---|
| Processor | Any dual-core CPU |
| RAM | 4 GB (8 GB used in this project) |
| Disk | 100 MB free |
| Network | Not needed for local testing; internet only for permitted real-site scans |

### 5.2 Software
| Item | Version |
|---|---|
| Operating system | Windows 11 |
| Python | 3.8 or newer |
| Library | `requests` (installed with pip) |
| Editor (optional) | Visual Studio Code |
| Browser | Any modern browser (to view the HTML report) |

## 6. Architecture and Workflow

### 6.1 Modules

| File | Role |
|---|---|
| `scanner.py` | Command-line interface, URL validation, safe request sending, header checks, CORS checks, scan orchestration |
| `report_generator.py` | Builds the JSON and HTML reports |
| `mock_server.py` | Local server with 11 test pages for safe testing |
| `tests/test_scanner.py` | 56 automated unit and integration tests |

### 6.2 Architecture diagram

```
 +-----------+     URL + options      +----------------------------+
 |   User    | ---------------------> |  scanner.py (CLI)          |
 | (Command  |                        |  1. Validate URL           |
 |  Prompt)  | <--------------------- |  2. Safety checks          |
 +-----------+   console summary      |  3. Send requests          |
       ^                              |  4. Analyse headers + CORS |
       |                              |  5. Build findings         |
       | opens HTML                   +-------------+--------------+
       |                                            |
 +-----+------------+        findings dictionary    v
 | reports\*.html   | <------------ +----------------------------+
 | reports\*.json   |               | report_generator.py        |
 +------------------+               +----------------------------+

   scanner.py  --- HTTP (GET x1 + CORS probes x3) --->  Target
                                                        (mock_server.py on
                                                         127.0.0.1, or a site
                                                         you have permission
                                                         to test)
```

### 6.3 Workflow

```
Start
  |
  v
Read URL and options  -->  Invalid? --> show error, stop
  |
  v
Resolve host name --> Private network? --> BLOCK, stop
  |                   Localhost without --allow-local? --> BLOCK, stop
  |                   Real site without --i-have-permission? --> BLOCK, stop
  v
Send GET request (timeout, max 3 same-host redirects)
  |            errors (timeout / connection / SSL) --> friendly message, stop
  v
Analyse security headers --> findings
  |
  v
CORS probes: (1) fake origin  (2) "null" origin  (3) OPTIONS preflight
  |
  v
Classify results, calculate summary + overall rating
  |
  v
Save JSON and HTML reports, print summary
  |
  v
End
```

## 7. Methodology

1. **Study:** Studied HTTP response headers, OWASP Secure Headers recommendations, MDN documentation and the CORS specification.
2. **Design:** Divided the program into small functions (validation, request sending, one function per header, CORS analysis, reporting) so each part can be tested separately.
3. **Safe requests:** Used the `requests` library with `stream=True` (only headers are read), a timeout, a 0.5 second delay, a 3-redirect limit and same-host redirects only.
4. **Header analysis:** Each header is classified as PASS, MISSING, WEAK or N/A. Examples of WEAK: CSP containing `'unsafe-inline'` or `*`; HSTS `max-age` below 180 days; `X-Content-Type-Options` other than `nosniff`; `Referrer-Policy: unsafe-url`.
5. **CORS analysis:** Send `Origin: https://untrusted-origin.example` (a reserved, non-existent name) and `Origin: null`, plus one OPTIONS preflight. Result rules:
   - no CORS headers -> PASS
   - wildcard `*` -> INFO (fine for public data)
   - copies origin back, no credentials -> WEAK
   - copies origin (or trusts `null`) **and** `Allow-Credentials: true` -> CONFIRMED misconfiguration
   - one specific trusted origin -> PASS
6. **Classification principle:** A missing header is a *hardening gap*, not a vulnerability. Only CORS behaviour that is clearly dangerous is labelled CONFIRMED, and nothing is exploited.
7. **Reporting:** Findings are stored in a dictionary, saved as JSON and rendered as HTML (all text HTML-escaped).
8. **Testing:** Built a mock server and wrote automated tests for headers, CORS, URL safety, error handling and reports.

## 8. Testing

### 8.1 Test environment
Tests were executed during development on **Linux, Python 3.12.3, requests 2.33.1**. Re-run them on your Windows 11 laptop and record your own result in the last column of the manual table (8.3).

### 8.2 Automated testing summary
Command: `python -m unittest discover -s tests -v`
Result when run during development: **56 tests run, 56 passed, 0 failed.**

| Test group | Tests | What is checked |
|---|---|---|
| Header checks | 16 | Present, missing, weak values, HSTS over HTTP, CSP frame-ancestors, information leaks |
| CORS analysis | 7 | No CORS, wildcard, wildcard+credentials, reflected origin (with/without credentials), `null`, trusted origin |
| URL safety | 11 | Empty/invalid URL, bad port, non-HTTP scheme, private and link-local IP blocked, localhost and permission rules |
| Mock-server scans | 17 | Full scans of every mock page, redirect, 404, timeout, refused connection, request limit, command-line behaviour |
| Reports | 5 | HTML content, HTML escaping, valid JSON, JSON-to-HTML conversion, missing-file handling |

### 8.3 Testing table (manual and key automated cases)

| ID | Test case | Input | Expected result | Result observed in development |
|---|---|---|---|---|
| T1 | All headers present | `/secure` | CSP, X-CTO, XFO, Referrer = PASS; HSTS = N/A (HTTP); rating GOOD | Pass |
| T2 | All headers missing | `/insecure` | CSP, X-CTO, XFO, Referrer = MISSING; `X-Powered-By` = INFO; no CONFIRMED | Pass |
| T3 | Weak headers | `/weak` | CSP, X-CTO, XFO, Referrer = WEAK | Pass |
| T4 | CORS wildcard | `/cors-wildcard` | INFO | Pass |
| T5 | CORS reflects origin + credentials | `/cors-reflect` | CONFIRMED, rating HIGH | Pass |
| T6 | CORS reflects origin, no credentials | `/cors-reflect-nocreds` | WEAK | Pass |
| T7 | CORS trusts `null` + credentials | `/cors-null` | CONFIRMED (null probe) | Pass |
| T8 | CORS specific trusted origin | `/cors-safe` | PASS | Pass |
| T9 | Redirect handling | `/redirect` | Follows to `/secure` | Pass |
| T10 | HTTP error page | `/does-not-exist` | Scan completes; INFO note about HTTP 404 | Pass |
| T11 | Timeout | `/slow` with 1 s timeout | Friendly "timed out" message | Pass |
| T12 | Connection refused | closed port | Friendly "Could not connect" message | Pass |
| T13 | Invalid URL | `ftp://example.com` | Rejected with message | Pass |
| T14 | Localhost without flag | `http://127.0.0.1:8000/` | Blocked, 0 requests sent | Pass |
| T15 | Private IP | host resolving to 192.168.x.x (simulated) | Always blocked | Pass |
| T16 | Real site without permission flag | public IP (simulated) | Blocked until `--i-have-permission` | Pass |
| T17 | Request limit | `/secure` | At most 4 requests (observed: 4: 3 GET + 1 OPTIONS) | Pass |
| T18 | HTML report safety | evidence = `<script>` text | Text escaped, not executed | Pass |
| T19 | Report files created | CLI scan of `/demo` | One `.json` and one `.html` file | Pass |
| T20 | *Your run on Windows 11* | `python -m unittest discover -s tests -v` | OK | `<fill in>` |

> **Honesty note for examiners:** T15 and T16 were tested with simulated DNS answers (Python `unittest.mock`) because they need specific IP addresses. The tool was tested against the local mock server only; scanning of real internet websites was **not** part of the development test run.

## 9. Results and Limitations

### 9.1 Results
- The scanner correctly classified all eleven mock pages as expected.
- Example result for `/demo`: 1 PASS, 3 MISSING, 1 WEAK, 3 CONFIRMED, 1 N/A; overall rating HIGH (see `sample_report.html`).
- The tool sent exactly four requests per scan (observed in the mock server log).
- Errors (timeout, refused connection, invalid URL, blocked target) produced clear messages and no crash.
- Reports were generated in both JSON and HTML formats.

### 9.2 Limitations
1. Header-only analysis; no page crawling, no cookie analysis, no TLS/certificate analysis.
2. A single URL is tested; other paths of a site may send different headers.
3. CORS testing is basic (three requests); it cannot see behaviour that depends on login state.
4. CSP analysis is simplified (nonces, hashes, `strict-dynamic` are not interpreted).
5. The overall rating is a heuristic, not a professional audit score.
6. DNS rebinding between the safety check and the request is not fully prevented.
7. Tested during development on Linux with the mock server; real-world sites may behave unexpectedly (CDNs, bot protection, rate limits).

## 10. Future Scope
- Scan several URLs from a file, with polite rate limiting.
- Add cookie-flag checks (`Secure`, `HttpOnly`, `SameSite`).
- Add TLS version and certificate-expiry checks.
- Parse CSP fully (nonces, hashes, `report-uri`).
- Add Cross-Origin-Opener-Policy / Embedder-Policy / Resource-Policy checks.
- Add a security score (0-100) and a PDF report.
- Build a small web dashboard (Flask) and a history of scans.
- Integrate into a CI/CD pipeline to fail builds when security headers regress.

## 11. Conclusion
The project delivers a working, beginner-friendly header and CORS auditing tool in Python. It explains each result, separates hardening gaps from confirmed misconfigurations, enforces safe and ethical use, and can be tested on the user's own laptop with a mock server. Automated tests (56 of 56 passing during development) demonstrate that the main behaviours work. The project shows that a few lines of configuration can greatly improve website security, and that security tools must themselves be designed to be safe and legal.

## 12. References
1. OWASP Secure Headers Project - <https://owasp.org/www-project-secure-headers/>
2. MDN Web Docs - HTTP headers, CORS - <https://developer.mozilla.org/>
3. RFC 6797 - HTTP Strict Transport Security (HSTS)
4. RFC 7034 - HTTP Header Field X-Frame-Options
5. W3C - Content Security Policy Level 3
6. Fetch Standard - CORS protocol - <https://fetch.spec.whatwg.org/>
7. Python `requests` documentation - <https://requests.readthedocs.io/>

*(Add your own sources and follow your college's reference format.)*

---

## 13. Screenshot Checklist

Take clear screenshots and label them as figures in the report.

- [ ] 1. `python --version` showing the Python version
- [ ] 2. Project folder in File Explorer or the VS Code explorer panel (all files visible)
- [ ] 3. Virtual environment created and activated (`(venv)` visible in the prompt)
- [ ] 4. `pip install -r requirements.txt` completed
- [ ] 5. Mock server running (`Mock server running at http://127.0.0.1:8000/`)
- [ ] 6. Mock server home page in a browser (`http://127.0.0.1:8000/`)
- [ ] 7. Scan of `/secure` in Command Prompt
- [ ] 8. Scan of `/insecure` in Command Prompt (MISSING findings)
- [ ] 9. Scan of `/weak` in Command Prompt (WEAK findings)
- [ ] 10. Scan of `/cors-reflect` (CONFIRMED CORS finding)
- [ ] 11. Safety block: scan without `--allow-local` (Blocked message)
- [ ] 12. Error handling: scan of a closed port, or `/slow --timeout 1`
- [ ] 13. `reports` folder showing the `.json` and `.html` files
- [ ] 14. HTML report open in the browser (top part: summary)
- [ ] 15. HTML report (findings with "Why it matters" and "Recommendation")
- [ ] 16. JSON report open in VS Code
- [ ] 17. Mock server window showing the logged requests (proves only a few requests were sent)
- [ ] 18. Automated tests: `python -m unittest discover -s tests -v` ending with `OK`
- [ ] 19. Source code of `scanner.py` (a few key functions) in VS Code

## 14. Viva Questions with Answers

**Q1. What is an HTTP security header?**
An instruction the server sends with its response that tells the browser to enable a protection, for example "only load scripts from my own domain" or "always use HTTPS".

**Q2. What does Content-Security-Policy do?**
It lists the sources from which a page may load scripts, images, frames and so on. It greatly reduces the impact of Cross-Site Scripting (XSS). `'unsafe-inline'` weakens it because injected inline scripts are allowed again.

**Q3. What is HSTS and why does it only apply to HTTPS?**
HSTS tells the browser to use only HTTPS for the site for a given time (`max-age`). It protects against SSL-stripping downgrade attacks. Browsers ignore it over plain HTTP, because an attacker could forge it there - so my tool marks it N/A for HTTP pages.

**Q4. What is clickjacking and which header stops it?**
Clickjacking tricks a user into clicking something hidden inside a frame. `X-Frame-Options: DENY/SAMEORIGIN` or the CSP directive `frame-ancestors` prevents the page from being framed by other sites.

**Q5. What does X-Content-Type-Options: nosniff do?**
It stops the browser from guessing a file's type, so a file served as plain text is not executed as a script.

**Q6. What is the Referrer-Policy header?**
It controls how much of the current page URL is sent in the `Referer` header to other sites. A strict policy prevents leaking URLs that may contain private data.

**Q7. What is CORS?**
Cross-Origin Resource Sharing. Browsers normally stop a page on site A from reading responses from site B (Same-Origin Policy). CORS headers let site B say which other origins may read its responses.

**Q8. Is CORS the same as the Same-Origin Policy?**
No. The Same-Origin Policy is the browser's default restriction. CORS is the controlled way to relax it.

**Q9. Why is "reflecting the Origin header with credentials" dangerous?**
The server tells every website "you may read my responses, including logged-in ones". A malicious site could make the victim's browser fetch private data and read it.

**Q10. Why is `Access-Control-Allow-Origin: *` only INFO in your tool?**
It is common and acceptable for public data. Browsers also refuse to combine `*` with credentials, so it is not directly exploitable. It is flagged for review, not as a confirmed problem.

**Q11. What is a preflight request?**
For some cross-origin requests the browser first sends an `OPTIONS` request asking which methods and headers are allowed. My tool sends one harmless preflight and only reads the answer.

**Q12. What is the difference between a missing header and a vulnerability?**
A missing header is a *hardening gap*: a protection layer is absent, but there may be no exploitable flaw. A vulnerability is an actual weakness that can be abused. My tool labels missing headers MISSING and only labels clearly dangerous observed behaviour CONFIRMED.

**Q13. Your tool says CONFIRMED. Did you exploit anything?**
No. CONFIRMED means the server's response itself clearly showed an insecure rule. I never read private data, log in, or send attack payloads.

**Q14. How does your tool stay ethical and safe?**
It requires `--i-have-permission` for real sites, blocks private networks and localhost unless allowed, uses a timeout, a delay and a 3-redirect limit, sends at most four requests, only follows redirects on the same host, and reads only headers.

**Q15. Why block private IP addresses?**
To prevent the tool from being misused to probe internal networks (a risk similar to Server-Side Request Forgery) and to stop accidental scanning of other people's devices.

**Q16. Why did you use `stream=True` in `requests`?**
It avoids downloading the page body. I only need the headers, so it is faster and lighter for the server.

**Q17. How do you handle errors?**
The `Requester` class converts timeouts, SSL errors, connection errors and invalid URLs into a friendly `ScanError`. `run_scan` catches it and puts the message in the result, so the program never shows a raw traceback.

**Q18. Why is a mock server needed?**
It lets me test every situation (good, missing, weak, risky CORS, redirects, slow pages) legally and repeatably on my own laptop, without scanning anyone's real website.

**Q19. Why does the mock server listen only on 127.0.0.1?**
127.0.0.1 is the loopback address; only programs on my own computer can connect. Other devices on the network cannot reach it.

**Q20. What is a virtual environment and why use it?**
An isolated Python installation for one project, so its libraries do not conflict with other projects. Created with `python -m venv venv`.

**Q21. How is your overall rating calculated?**
HIGH if any CONFIRMED finding; otherwise MEDIUM if a missing/weak finding has medium severity; otherwise LOW if anything is missing/weak; otherwise GOOD. It is a simple guide, not an audit score.

**Q22. What are the main limitations?**
Header-only analysis; one URL; basic CORS testing; simplified CSP parsing; no cookie or TLS checks; tested on a mock server in development rather than on real sites.

**Q23. How could the project be improved?**
Add cookie and TLS checks, full CSP parsing, multi-URL scans, a security score, PDF reports and a web dashboard.

**Q24. Which Python concepts did you use?**
Functions, dictionaries and lists, classes (`Requester`, request handler), exceptions (`try/except`), command-line parsing (`argparse`), file handling, regular expressions, threads (in tests) and the `unittest` framework.

**Q25. How did you test the project?**
With 56 automated tests (`unittest`) covering headers, CORS, URL safety, error handling and reports, plus manual scans of all mock pages and inspection of the mock server log.
