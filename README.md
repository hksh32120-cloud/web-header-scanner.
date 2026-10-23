# Automated Web Security Header Scanner (Python)

A beginner-friendly cybersecurity tool that audits a website's **HTTP security headers** and performs a **cautious, basic CORS check**. It creates a **JSON report** and a readable **HTML report**.

> **Legal and ethical notice:** Only scan websites that you **own** or have **written permission** to test. Scanning other people's systems without permission may be illegal. For learning, use the included local mock server — it never touches the internet.

---

## 1. What the tool does

| Feature | Details |
|---|---|
| Header checks | Content-Security-Policy, Strict-Transport-Security (HSTS), X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, plus information-leak headers (`Server`, `X-Powered-By`) |
| CORS checks | 3 harmless requests: fake origin, `null` origin, one `OPTIONS` preflight |
| Honest labels | `MISSING` / `WEAK` = hardening gap (**not** a confirmed vulnerability). `CONFIRMED` = clearly insecure behaviour seen in the response. Nothing is ever exploited |
| Safety | 8-second timeout, 0.5 s delay between requests, max 3 redirects, private networks always blocked, real sites need `--i-have-permission` |
| Reports | `reports\scan_<host>_<time>.json` and `.html` |
| Dependencies | Only one: `requests` |

### Status labels

| Status | Meaning |
|---|---|
| PASS | Secure setting seen |
| MISSING | Header absent. A hardening gap, **not** a confirmed vulnerability |
| WEAK | Header present but badly configured. Also not a confirmed vulnerability |
| CONFIRMED | Insecure behaviour observed (e.g. server trusts any website *and* allows credentials). Not exploited |
| INFO | Needs a human to review |
| N/A | Check does not apply (e.g. HSTS over plain HTTP) |

---

## 2. Project structure

```
web-header-scanner\
|-- scanner.py            main scanner (command line)
|-- report_generator.py   creates JSON + HTML reports
|-- mock_server.py        local test server (safe practice target)
|-- requirements.txt      dependency list
|-- README.md             this file
|-- PROJECT_REPORT.md     college report template
|-- sample_report.html    example output
|-- reports\              created automatically when you scan
|-- tests\
    |-- test_scanner.py   56 automated tests
```

---

## 3. Windows 11 setup, step by step

### Step 1 - Check whether Python is installed
1. Press the **Windows key**, type `cmd`, press **Enter** (this opens *Command Prompt*).
2. Type this and press Enter:
   ```
   python --version
   ```
3. If you see something like `Python 3.12.x` (3.8 or newer is fine), skip to Step 3.
4. If you see *"Python was not found"* (or the Microsoft Store opens), go to Step 2.

### Step 2 - Install Python
1. Open <https://www.python.org/downloads/> and click **Download Python 3.x**.
2. Run the installer. **Very important:** tick **"Add python.exe to PATH"** on the first screen, then click **Install Now**.
3. When finished, **close Command Prompt and open a new one**, then run `python --version` again. It should now show a version.

### Step 3 - Create the project folder and files
1. In Command Prompt run:
   ```
   cd %USERPROFILE%\Documents
   mkdir web-header-scanner
   cd web-header-scanner
   mkdir tests
   ```
2. Copy the files into this folder. (If you downloaded the ZIP, just extract it here.) If creating them by hand, use **VS Code** (below) or Notepad and save with **exactly** these names: `scanner.py`, `report_generator.py`, `mock_server.py`, `requirements.txt`, `README.md`, `PROJECT_REPORT.md`, and `tests\test_scanner.py`.
   - In Notepad, choose *Save as type: All files* so Windows does not add `.txt`.

**Optional - use VS Code:** install it from <https://code.visualstudio.com/>, then in Command Prompt inside the project folder run `code .`. VS Code opens the folder; use **Terminal > New Terminal** for the commands below.

### Step 4 - Create and activate a virtual environment
A virtual environment keeps this project's libraries separate from the rest of your computer.
```
python -m venv venv
venv\Scripts\activate
```
Your prompt now starts with `(venv)`. 

> **PowerShell error about "running scripts is disabled"?** Either use *Command Prompt* instead, or run this once in that PowerShell window and try again:
> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

### Step 5 - Install the dependency
```
pip install -r requirements.txt
```

### Step 6 - Start the local test server (Window 1)
```
python mock_server.py
```
You should see: `Mock server running at http://127.0.0.1:8000/`. **Leave this window open.** (Stop it later with `Ctrl+C`.)
If Windows Firewall asks, you may click **Cancel/Block**; the server only listens on your own laptop.

### Step 7 - Run the scanner (Window 2)
Open a **new** Command Prompt, then:
```
cd %USERPROFILE%\Documents\web-header-scanner
venv\Scripts\activate
python scanner.py http://127.0.0.1:8000/demo --allow-local
```
Try the other test pages too:
```
python scanner.py http://127.0.0.1:8000/secure --allow-local
python scanner.py http://127.0.0.1:8000/insecure --allow-local
python scanner.py http://127.0.0.1:8000/weak --allow-local
python scanner.py http://127.0.0.1:8000/cors-reflect --allow-local
python scanner.py http://127.0.0.1:8000/cors-wildcard --allow-local
python scanner.py http://127.0.0.1:8000/cors-safe --allow-local
```

### Step 8 - Open the reports
The scanner prints the report names at the end. Reports are inside the `reports` folder:
```
dir reports
start "" "reports\scan_127.0.0.1_8000_YYYYMMDD_HHMMSS.html"
```
(Replace the file name with the real one printed by the scanner.) Or open the `reports` folder in File Explorer and double-click the `.html` file.

To rebuild an HTML report from an existing JSON file:
```
python report_generator.py reports\your_scan.json reports\rebuilt.html
```

### Step 9 - Run the automated tests
Stop nothing - the tests start their own temporary server. In the project folder (venv active):
```
python -m unittest discover -s tests -v
```
At the end you should see `OK`. 

---

## 4. Scanning a real website (only with permission)

```
python scanner.py https://your-own-site.example --i-have-permission
```
Without `--i-have-permission`, the tool refuses. Private addresses (192.168.x.x, 10.x.x.x, 172.16-31.x.x, 169.254.x.x) are **always** blocked.

### All options
| Option | Meaning |
|---|---|
| `url` | Target URL (required) |
| `--timeout N` | Seconds to wait per request (1-60, default 8) |
| `--output-dir FOLDER` | Where to save reports (default `reports`) |
| `--allow-local` | Allow `localhost` / `127.0.0.1` (mock server) |
| `--i-have-permission` | You confirm you own the site or have written permission |

---

## 5. Mock server test pages

| Page | What it simulates | Expected scanner result |
|---|---|---|
| `/secure` | All headers correct | All PASS (HSTS = N/A over HTTP) |
| `/insecure` | No headers, leaks `X-Powered-By` | MISSING headers, no CONFIRMED |
| `/weak` | Badly configured headers | WEAK headers |
| `/demo` | Mixed headers + risky CORS | Mix, rating HIGH |
| `/cors-wildcard` | `Access-Control-Allow-Origin: *` | INFO |
| `/cors-reflect` | Copies any Origin + credentials | CONFIRMED |
| `/cors-reflect-nocreds` | Copies any Origin, no credentials | WEAK |
| `/cors-null` | Trusts `null` + credentials | CONFIRMED (null probe) |
| `/cors-safe` | Allows only one trusted origin | PASS |
| `/redirect` | Redirects to `/secure` | Redirect followed |
| `/slow` | Answers after 3 s | Timeout error with `--timeout 1` |

---

## 6. Troubleshooting

| Problem | Fix |
|---|---|
| `'python' is not recognized` | Reinstall Python and tick *Add python.exe to PATH*; open a new Command Prompt |
| `No module named requests` | Activate the venv (`venv\Scripts\activate`) then `pip install -r requirements.txt` |
| `Could not connect` | Is the mock server running in the other window? Same port? |
| `Blocked: ... localhost` | Add `--allow-local` |
| Port 8000 already used | `python mock_server.py --port 8001` and scan `http://127.0.0.1:8001/...` |
| Timeout on a real site | Try `--timeout 20`; check your internet connection |

---

## 7. Limitations (be honest in your viva!)

- It checks **response headers only**; it does not crawl pages or test login areas.
- A header check shows configuration, **not** proof of a vulnerability. Only the `CONFIRMED` CORS results show clearly insecure behaviour, and even those were not exploited.
- CORS testing is basic: one URL, three requests. Real APIs may behave differently per path, per method, or when logged in.
- The CSP analysis is simple (it does not understand nonces, hashes or `strict-dynamic`).
- Host names are resolved and checked just before each request; a determined attacker controlling DNS could change the answer in between (DNS rebinding). This is a known limit of simple tools.
- The overall rating is a rough guide, not a professional audit.

## 8. License / use
Educational project. Use responsibly and legally.
