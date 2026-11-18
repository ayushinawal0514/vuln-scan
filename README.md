# Automated Vulnerability Scanner (ET 401 Project)

A Flask web app that runs a small set of **safe, read-only** security-configuration checks
(HTTPS, HTTP->HTTPS redirect, security headers, cookie attributes, server-info disclosure)
on **approved targets only** (localhost / explicitly configured lab hosts).

## Setup (Windows / VS Code)
1. Install Python 3.10+ (tick "Add to PATH").
2. Open this folder in VS Code (File > Open Folder).
3. Terminal > New Terminal, then:
   ```
   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   ```
   (PowerShell blocked? run `Set-ExecutionPolicy -Scope Process Bypass` first.)
4. Terminal 1:  `python test_server.py`   (lab target on http://127.0.0.1:5001)
5. Terminal 2:  `python app.py`           (scanner on http://127.0.0.1:5000)
6. Open http://127.0.0.1:5000 and scan `http://127.0.0.1:5001/insecure`.

Or in VS Code: Run and Debug > "Run Scanner + Lab Target".

## Lab target pages
`/secure` (good headers/cookie), `/insecure` (nothing set, version leaks, bad cookies),
`/redirect-local`, `/redirect-out` (must be blocked), `/slow` (timeout test).

## Allow another lab host (only one you own!)
`set LAB_HOSTS=mylab.local` (cmd) or `$env:LAB_HOSTS="mylab.local"` (PowerShell) before `python app.py`.

## Tests
`python -m unittest -v`

## Layout
`app.py` routes | `config.py` limits | `scanner/policy.py` allowlist | `scanner/engine.py` safe client + controller |
`scanner/checks.py` checks | `scanner/severity.py` rules | `database.py` SQLite | `reports.py` CSV/PDF | `templates/` UI

## Limitations
Limited checks only; findings are potential and need manual verification; severity is rule-based, NOT CVSS;
no findings does not mean the app is secure.
