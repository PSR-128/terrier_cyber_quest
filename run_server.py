"""
Server Launcher for Terrier Cyber Quest.
Starts the FastAPI Backend and Dashboard Server on http://127.0.0.1:8000
Optionally starts the staging test target on http://127.0.0.1:5000 in a background process.
"""

import sys
import uvicorn
import multiprocessing

def run_staging_app():
    from sample_vulnerable_app.app import app as staging_app
    uvicorn.run(staging_app, host="127.0.0.1", port=5000, log_level="warning")

def run_main_app():
    from backend.api.app import app as main_app
    print("\n" + "="*70)
    print(" [*] TERRIER CYBER QUEST -- AI CYBER-REASONING PLATFORM")
    print("="*70)
    print(" Dashboard & API Server: http://127.0.0.1:8000")
    print(" Staging Target (Local): http://127.0.0.1:5000")
    print(" Authorized Scope Only.")
    print("="*70 + "\n")
    uvicorn.run(main_app, host="127.0.0.1", port=8000, log_level="info")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--staging-only":
        run_staging_app()
    elif len(sys.argv) > 1 and sys.argv[1] == "--backend-only":
        run_main_app()
    else:
        # Start staging app in child process and main backend in foreground
        p = multiprocessing.Process(target=run_staging_app, daemon=True)
        p.start()
        run_main_app()
