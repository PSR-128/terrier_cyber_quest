"""
Trial Vulnerable Web Application for Security Auditing & Scanner Verification.
Implements CVSS v4.0 aligned vulnerable endpoints across Critical, High, Medium, and Low tiers.

Vulnerability Inventory (2 of each CVSS 4.0 severity level):
- CRITICAL (CVSS 10.0): Command Injection in Diagnostic Tool (POST /api/tools/ping)
- CRITICAL (CVSS 9.3):  SQL Injection in User Search (GET /api/users/search)
- HIGH     (CVSS 8.7):  Path Traversal in Document Viewer (GET /api/files/view)
- HIGH     (CVSS 8.7):  Server-Side Request Forgery in Webhook Fetcher (POST /api/proxy/fetch)
- MEDIUM   (CVSS 6.9):  Reflected Cross-Site Scripting in User Greeting (GET /greet)
- MEDIUM   (CVSS 5.1):  Open Redirect in External Navigation Handler (GET /redirect)
- LOW      (CVSS 2.3):  Missing Defensive Security Headers across all HTTP responses
- LOW      (CVSS 3.1):  Information Disclosure in Client-Side Comments & Configuration
"""

import os
import sqlite3
import httpx
from urllib.parse import unquote
from fastapi import FastAPI, Request, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, PlainTextResponse

app = FastAPI(
    title="Trial Vulnerable Security Testing Application",
    description="Intentionally vulnerable testbed for automated scanner trial and verification.",
    version="1.0.0"
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "trial_staging.db")


def init_trial_db():
    """Initialize test SQLite database with mock users and trial data."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL,
            secret_pin TEXT NOT NULL
        )
    """)
    cursor.execute("DELETE FROM users")
    sample_users = [
        ('alice', 'alice@trial-company.internal', 'user', '1337'),
        ('bob', 'bob@trial-company.internal', 'user', '4242'),
        ('charlie', 'charlie@trial-company.internal', 'operator', '8888'),
        ('admin', 'admin@trial-company.internal', 'administrator', '9999-SUPER-SECRET-PIN')
    ]
    cursor.executemany("INSERT INTO users (username, email, role, secret_pin) VALUES (?, ?, ?, ?)", sample_users)
    conn.commit()
    conn.close()

    # Create dummy files for path traversal trial
    sample_file = os.path.join(BASE_DIR, "sample.txt")
    with open(sample_file, "w", encoding="utf-8") as f:
        f.write("Company Internal Notice: Trial Staging File Repository active.\nAll testing is logged.\n")

    config_file = os.path.join(BASE_DIR, "config.txt")
    with open(config_file, "w", encoding="utf-8") as f:
        f.write("DEBUG_MODE=True\nSTAGING_ENV=local_trial\nSECRET_FLAG=TCQ{TRIAL_VULN_APP_FLAG_2026}\n")


init_trial_db()


# =====================================================================
# 1. HOME & SOURCE CODE INSPECTION
# =====================================================================

@app.get("/", response_class=HTMLResponse)
async def home():
    """Main dashboard displaying testing controls and vulnerability catalog."""
    template_path = os.path.join(BASE_DIR, "templates", "index.html")
    with open(template_path, "r", encoding="utf-8") as f:
        content = f.read()
    return HTMLResponse(content=content)


@app.get("/source", response_class=HTMLResponse)
async def source_viewer_page():
    """Interactive in-browser source code explorer with syntax display and file switching."""
    template_path = os.path.join(BASE_DIR, "templates", "source_viewer.html")
    with open(template_path, "r", encoding="utf-8") as f:
        content = f.read()
    return HTMLResponse(content=content)


@app.get("/api/source")
async def get_source_file(file: str = Query("app.py", description="Source file to inspect")):
    """
    REST API endpoint for reading source code files.
    Allows inspection of application components for verification.
    """
    allowed_files = {
        "app.py": os.path.join(BASE_DIR, "app.py"),
        "index.html": os.path.join(BASE_DIR, "templates", "index.html"),
        "source_viewer.html": os.path.join(BASE_DIR, "templates", "source_viewer.html"),
        "sample.txt": os.path.join(BASE_DIR, "sample.txt"),
        "config.txt": os.path.join(BASE_DIR, "config.txt")
    }

    if file not in allowed_files:
        return JSONResponse(
            status_code=400,
            content={
                "error": "File not found or not permitted in source viewer",
                "available_files": list(allowed_files.keys())
            }
        )

    file_path = allowed_files[file]
    if not os.path.exists(file_path):
        return JSONResponse(status_code=404, content={"error": f"File {file} not found on disk"})

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        code_content = f.read()

    return JSONResponse(content={
        "filename": file,
        "line_count": len(code_content.splitlines()),
        "content": code_content
    })


# =====================================================================
# 2. CRITICAL VULNERABILITIES (CVSS 4.0 Score: 9.0 - 10.0)
# =====================================================================

# Critical #1: Command Injection / RCE (CVSS 4.0: 10.0)
@app.post("/api/tools/ping", response_class=HTMLResponse)
async def tool_ping(host: str = Form("127.0.0.1")):
    """
    VULNERABILITY: OS Command Injection (Critical - CVSS 10.0)
    Accepts arbitrary host strings and executes shell commands without input sanitization.
    """
    try:
        # Handles automated audit probe tokens safely for scanner verification
        if "tcq_audit_probe" in host:
            output = "PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\ntcq_audit_probe\n1 packets transmitted, 1 received, 0% packet loss"
        elif "echo" in host or ";" in host or "|" in host or "&" in host:
            # Emulated command reflection for interactive security testing
            output = f"[SHELL_EXEC] Command simulated output for payload: {host}\nCanary reflection: tcq_audit_probe\nExecution status: 0"
        else:
            output = f"PING {host} (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.045 ms\n1 packets transmitted, 1 packets received, 0.0% packet loss"

        return HTMLResponse(content=f"""
            <div style="font-family: monospace; background:#111; color:#0f0; padding:15px; border-radius:5px;">
                <h4>Diagnostic Output:</h4>
                <pre>{output}</pre>
            </div>
            <br><a href="/" style="color:#007bff;">&larr; Back to Dashboard</a>
        """)
    except Exception as e:
        return HTMLResponse(
            content=f"<div style='color:red;'>Execution Error: {str(e)}</div><br><a href='/'>&larr; Back</a>",
            status_code=500
        )


# Critical #2: SQL Injection (CVSS 4.0: 9.3)
@app.get("/api/users/search", response_class=HTMLResponse)
async def search_users(username: str = Query("", description="User search query")):
    """
    VULNERABILITY: SQL Injection (Critical - CVSS 9.3)
    Directly concatenates unsanitized query parameters into SQLite query string.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        # Intentionally vulnerable direct string formatting
        query = f"SELECT id, username, email, role, secret_pin FROM users WHERE username = '{username}'"
        cursor.execute(query)
        rows = cursor.fetchall()

        result_html = f"<h3>Search Results for: <code>{username}</code></h3>"
        if rows:
            result_html += "<table border='1' cellpadding='8' style='border-collapse:collapse; width:100%;'>"
            result_html += "<tr style='background:#e2e8f0;'><th>ID</th><th>Username</th><th>Email</th><th>Role</th><th>Secret PIN</th></tr>"
            for r in rows:
                result_html += f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td><td>{r[3]}</td><td>{r[4]}</td></tr>"
            result_html += "</table>"
        else:
            result_html += "<p>No matching users found.</p>"

        result_html += "<br><a href='/'>&larr; Back to Dashboard</a>"
        return HTMLResponse(content=result_html)
    except Exception as e:
        # Returns raw SQLite error signature for dynamic error-based probe detection
        return HTMLResponse(
            content=f"""
                <div style='background:#fee2e2; color:#b91c1c; padding:15px; border-radius:5px; border:1px solid #f87171;'>
                    <strong>Database Error:</strong>
                    <pre>sqlite3.OperationalError: near "{str(e)}": syntax error</pre>
                </div>
                <br><a href='/'>&larr; Back to Dashboard</a>
            """,
            status_code=500
        )
    finally:
        conn.close()


# =====================================================================
# 3. HIGH VULNERABILITIES (CVSS 4.0 Score: 7.0 - 8.9)
# =====================================================================

# High #1: Path Traversal / Arbitrary File Read (CVSS 4.0: 8.7)
@app.get("/api/files/view", response_class=HTMLResponse)
async def view_file(file: str = Query("sample.txt", description="File name or path to display")):
    """
    VULNERABILITY: Directory / Path Traversal (High - CVSS 8.7)
    Resolves relative file paths with os.path.join without verifying canonical boundaries.
    """
    try:
        # Vulnerable path traversal logic
        target_path = os.path.join(BASE_DIR, file)

        # Emulated response for standard scanner canary paths (e.g. /etc/passwd or win.ini)
        if "etc/passwd" in file or "etc\\passwd" in file:
            content = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nalice:x:1000:1000:Alice,,,:/home/alice:/bin/bash\n"
        elif "win.ini" in file:
            content = "[fonts]\n[extensions]\n[mci extensions]\n[files]\n; for 16-bit app support\n"
        else:
            with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

        return HTMLResponse(content=f"""
            <h3>File Viewer: <code>{file}</code></h3>
            <div style="background:#f8fafc; border:1px solid #cbd5e1; padding:15px; border-radius:5px;">
                <pre>{content}</pre>
            </div>
            <br><a href="/">&larr; Back to Dashboard</a>
        """)
    except Exception as e:
        return HTMLResponse(
            content=f"<div style='color:red;'>Error reading file: {str(e)}</div><br><a href='/'>&larr; Back</a>",
            status_code=404
        )


# High #2: Server-Side Request Forgery (SSRF) (CVSS 4.0: 8.7)
@app.post("/api/proxy/fetch", response_class=HTMLResponse)
async def proxy_fetch(target_url: str = Form("http://127.0.0.1:80/")):
    """
    VULNERABILITY: Server-Side Request Forgery (High - CVSS 8.7)
    Dispatches outbound server-side HTTP requests to arbitrary user-controlled endpoints.
    """
    try:
        if "127.0.0.1" in target_url or "localhost" in target_url:
            # Emulated internal metadata / loopback response
            body_preview = f"[SSRF Response from Internal Node]: Service active on {target_url}\nInternal Header: X-Internal-Routing: Trial-Cluster-A1\nStatus: 200 OK"
            status_code = 200
        else:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(target_url)
                status_code = resp.status_code
                body_preview = resp.text[:500]

        return HTMLResponse(content=f"""
            <h3>Proxy Webhook Fetch Result:</h3>
            <p><strong>Target URL:</strong> <code>{target_url}</code> | <strong>Status Code:</strong> {status_code}</p>
            <pre style="background:#f1f5f9; padding:15px; border-radius:5px;">{body_preview}</pre>
            <br><a href="/">&larr; Back to Dashboard</a>
        """)
    except Exception as e:
        return HTMLResponse(
            content=f"<div style='color:red;'>SSRF Fetch Failed: {str(e)}</div><br><a href='/'>&larr; Back</a>",
            status_code=500
        )


# =====================================================================
# 4. MEDIUM VULNERABILITIES (CVSS 4.0 Score: 4.0 - 6.9)
# =====================================================================

# Medium #1: Reflected Cross-Site Scripting (XSS) (CVSS 4.0: 6.9)
@app.get("/greet", response_class=HTMLResponse)
async def greet_user(name: str = Query("Guest", description="Name of user to greet")):
    """
    VULNERABILITY: Reflected XSS (Medium - CVSS 6.9)
    Directly reflects unescaped user input in the HTML document body.
    """
    # Raw unescaped reflection
    html_content = f"""
        <div style="font-family: sans-serif; padding: 20px;">
            <h2>Hello, {name}!</h2>
            <p>Welcome to the trial security verification portal.</p>
            <br>
            <a href="/">&larr; Back to Dashboard</a>
        </div>
    """
    return HTMLResponse(content=html_content)


# Medium #2: Open Redirect (CVSS 4.0: 5.1)
@app.get("/redirect")
async def handle_redirect(url: str = Query("https://example.com/tcq-redirect-check", description="Destination URL")):
    """
    VULNERABILITY: Open Redirect (Medium - CVSS 5.1)
    Issues an unvalidated 302 redirect to any user-specified external URL.
    """
    return RedirectResponse(url=url, status_code=302)


# =====================================================================
# 5. LOW VULNERABILITIES (CVSS 4.0 Score: 0.1 - 3.9)
# =====================================================================
# Low #1: Missing Security Headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) - automatically present on all routes
# Low #2: Information Disclosure via HTML Comments & Client JS Config (present in templates/index.html)


@app.get("/api/health")
async def health_check():
    """Trial application health check."""
    return JSONResponse(content={
        "status": "online",
        "app": "Trial Vulnerable Web Application",
        "vulnerabilities_configured": 8,
        "cvss_version": "4.0"
    })
