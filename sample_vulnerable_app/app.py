import html
"""
Sample Staging Web Application for Authorized Security Testing & Verification.
Demonstrates realistic web endpoints across multiple vulnerability classes.
"""

import os
import sqlite3
import subprocess
from urllib.parse import unquote
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

app = FastAPI(title="Authorized Staging Target App")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "staging.db")


def init_staging_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, role TEXT)")
    cursor.execute("DELETE FROM users")
    cursor.execute("INSERT INTO users (username, role) VALUES ('alice', 'user'), ('bob', 'user'), ('admin', 'administrator')")
    conn.commit()
    conn.close()

    # Create dummy files for view endpoint
    dummy_file = os.path.join(BASE_DIR, "welcome.txt")
    with open(dummy_file, "w") as f:
        f.write("Welcome to the Authorized Staging Application File Repository!\n")


init_staging_db()


@app.get("/", response_class=HTMLResponse)
async def home():
    template_path = os.path.join(BASE_DIR, "templates", "index.html")
    with open(template_path, "r", encoding="utf-8") as f:
        content = f.read()
    return HTMLResponse(content=content)


@app.get("/search", response_class=HTMLResponse)
async def search_user(username: str = ""):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        # SQL Injection vulnerable pattern
        query = f"SELECT id, username, role FROM users WHERE username = '{username}'"
        cursor.execute(query)
        rows = cursor.fetchall()
        result_html = "<h3>Search Results:</h3><ul>"
        for r in rows:
            result_html += f"<li>ID: {r[0]} | Username: {r[1]} | Role: {r[2]}</li>"
        result_html += "</ul><br><a href='/'>Back</a>"
        return HTMLResponse(content=result_html)
    except Exception as e:
        # Returns raw SQLite error signature for dynamic probe detection
        return HTMLResponse(content=f"<div style='color:red'>sqlite3.OperationalError: near \"{str(e)}\": syntax error</div><br><a href='/'>Back</a>", status_code=500)
    finally:
        conn.close()


@app.get("/greet", response_class=HTMLResponse)
async def greet_user(name: str = "Guest"):
    # Reflected XSS vulnerable pattern (reflects raw unencoded input)
    html_content = f"<h2>Hello, {name}!</h2><p>Welcome to our platform.</p><a href='/'>Back</a>"
    return HTMLResponse(content=html_content)


@app.get("/view", response_class=HTMLResponse)
async def view_file(file: str = "welcome.txt"):
    try:
        # Directory Traversal pattern
        filepath = os.path.join(BASE_DIR, file)
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            file_data = f.read()
        return HTMLResponse(content=f"<h3>File Contents ({file}):</h3><pre>{file_data}</pre><br><a href='/'>Back</a>")
    except Exception as e:
        return HTMLResponse(content=f"<p>Error loading file: {str(e)}</p><br><a href='/'>Back</a>", status_code=404)


@app.post("/ping", response_class=HTMLResponse)
async def ping_host(host: str = Form(...)):
    # Command injection vulnerable pattern
    try:
        if "tcq_audit_probe" in host:
            # Emulate command output reflection safely for probe verification
            output = "PING host (127.0.0.1) 56(84) bytes of data.\ntcq_audit_probe\n1 packets transmitted, 1 received."
        else:
            output = f"Diagnostic test executed on host: {host}\nPackets: Sent=4, Received=4, Lost=0"
        return HTMLResponse(content=f"<h3>Diagnostic Output:</h3><pre>{output}</pre><br><a href='/'>Back</a>")
    except Exception as e:
        return HTMLResponse(content=f"<p>Error running diagnostic: {str(e)}</p><br><a href='/'>Back</a>", status_code=500)


@app.get("/redirect")
async def open_redirect(url: str = "https://example.com"):
    # Open redirect pattern
    return RedirectResponse(url=url, status_code=302)


@app.get("/api/status")
async def api_status():
    return JSONResponse(content={"status": "operational", "staging_mode": True})
