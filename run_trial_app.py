"""
Launcher for the Trial Vulnerable Web Application.
Runs the CVSS v4.0 aligned testbed on http://127.0.0.1:5050 (or custom port).
"""

import sys
import argparse
import uvicorn
from trial_vulnerable_app.app import app

def main():
    parser = argparse.ArgumentParser(description="Run Trial Vulnerable Web Application for Security Auditing")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5050, help="Port to bind (default: 5050)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload on code changes")
    args = parser.parse_args()

    print("\n" + "=" * 75)
    print(" 🎯 TRIAL VULNERABLE WEB APPLICATION (CVSS 4.0 ALIGNED)")
    print("=" * 75)
    print(f" Web Application URL : http://{args.host}:{args.port}")
    print(f" Source Code Viewer  : http://{args.host}:{args.port}/source")
    print(f" API Health Endpoint : http://{args.host}:{args.port}/api/health")
    print(" Configured Vulnerabilities: 8 (2 Critical, 2 High, 2 Medium, 2 Low)")
    print("=" * 75 + "\n")

    uvicorn.run(app, host=args.host, port=args.port, reload=args.reload, log_level="info")

if __name__ == "__main__":
    main()
