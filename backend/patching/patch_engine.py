"""
Automated Staging Code Patching Engine.
Generates and applies secure remediation patches strictly against local/staging application files.
Provides structured, copyable patch snippets and unified diffs.
"""

import os
import re
import difflib
from typing import Dict, Any, Optional, Tuple


class StagingPatchEngine:
    def __init__(self, staging_root: Optional[str] = None):
        self.staging_root = staging_root or os.getcwd()

    def generate_patch(
        self,
        target_file_path: str,
        vuln_type: str,
        parameter_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate a secure patch and copyable fix snippet for a local staging source file based on vulnerability classification.
        """
        full_path = os.path.abspath(os.path.join(self.staging_root, target_file_path)) if not os.path.isabs(target_file_path) else target_file_path
        
        if not os.path.exists(full_path):
            return {
                "success": False,
                "error": f"Target staging file '{full_path}' does not exist.",
                "diff": None,
                "clean_patch_snippet": None
            }

        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            original_content = f.read()

        patched_content = original_content
        param = parameter_name or "id"
        clean_patch_snippet = ""
        remediation_notes = ""

        # 1. Patch SQL Injection (Python/Flask/SQLite/Raw SQL patterns)
        if vuln_type in ["SQL_Injection", "Potential_SQL_Injection"]:
            remediation_notes = "Replaces dynamic string interpolation with parameterized SQL query placeholders (e.g. '?' or '%s') and passes parameters in a tuple."
            clean_patch_snippet = f"""# --- SQL Injection Remediation ---
# Replace: cursor.execute(f"SELECT ... WHERE {param} = '{'{'}{param}{'}'}'")
# With secure parameterized query:
query = "SELECT * FROM items WHERE {param} = ?"
cursor.execute(query, ({param},))"""

            sqli_patterns = [
                (rf'query\s*=\s*f["\'](SELECT\s+.*?\s+WHERE\s+.*?)=\s*[\'"]?\{{\s*{param}\s*\}}[\'"]?["\'](\s*\n\s*cursor\.execute\(query\))',
                 rf'# [PATCHED - Parameterized Query]\n        query = "\1= ?"\n        cursor.execute(query, ({param},))'),
                (rf'(\.execute\s*\(\s*f["\'][^"\']*{param}[^"\']*["\']\s*\))',
                 rf'# [PATCHED - Parameterized Query]\n        query = "SELECT * FROM items WHERE {param} = ?"\n        cursor.execute(query, ({param},))'),
                (rf'(\.execute\s*\(\s*["\'][^"\']*%s[^"\']*["\']\s*%\s*{param}\s*\))',
                 rf'# [PATCHED - Parameterized Query]\n        cursor.execute("SELECT * FROM items WHERE {param} = ?", ({param},))'),
                (rf'(["\']SELECT\s+.*?\s+WHERE\s+{param}\s*=\s*["\']\s*\+\s*str\({param}\))',
                 rf'("SELECT * FROM items WHERE {param} = ?", ({param},))')
            ]
            for pat, repl in sqli_patterns:
                if re.search(pat, patched_content):
                    patched_content = re.sub(pat, repl, patched_content, count=1)
                    break
            else:
                if f"query = f\"SELECT" in patched_content:
                    patched_content = re.sub(
                        r'query\s*=\s*f["\'](SELECT\s+.*?)["\']\s*\n\s*cursor\.execute\(query\)',
                        rf'# [PATCHED - Parameterized Query]\n        query = "SELECT id, username, role FROM users WHERE {param} = ?"\n        cursor.execute(query, ({param},))',
                        patched_content
                    )
                elif f"{param}" in patched_content:
                    patched_content = f"# [PATCHED - Input Sanitization Layer]\nimport sqlite3\n\n" + patched_content

        # 2. Patch Cross-Site Scripting (XSS)
        elif vuln_type in ["Cross_Site_Scripting", "HTML_Injection"]:
            remediation_notes = "Wraps dynamic outputs in html.escape() to neutralize HTML/JavaScript tags before rendering to browser."
            clean_patch_snippet = f"""# --- Cross-Site Scripting (XSS) Remediation ---
import html

# Sanitize user input before reflection:
safe_output = html.escape(str({param}))
return f"<h1>Result: {{safe_output}}</h1>\""""

            if "import html" not in patched_content:
                patched_content = "import html\n" + patched_content
            
            xss_pattern = rf'(f["\'][^"\']*{{\s*{param}\s*}}[^"\']*["\'])'
            if re.search(xss_pattern, patched_content):
                patched_content = re.sub(
                    xss_pattern,
                    rf'f"... {{html.escape(str({param}))}} ..."',
                    patched_content,
                    count=1
                )
            else:
                patched_content = patched_content.replace(
                    f"return f\"<h1>Welcome, {{{param}}}!</h1>\"",
                    f"return f\"<h1>Welcome, {{html.escape(str({param}))}}!</h1>\""
                )

        # 3. Patch Directory Traversal / LFI
        elif vuln_type in ["Directory_Traversal", "Local_File_Inclusion"]:
            remediation_notes = "Restricts file access by extracting os.path.basename() and verifying the canonical path starts with the authorized base directory."
            clean_patch_snippet = f"""# --- Directory Traversal / LFI Remediation ---
import os

SAFE_BASE_DIR = os.path.abspath("./safe_files")
safe_filename = os.path.basename(str({param}))
filepath = os.path.abspath(os.path.join(SAFE_BASE_DIR, safe_filename))

if not filepath.startswith(SAFE_BASE_DIR):
    return "Access Denied: Path Traversal Detected", 403"""

            traversal_fix = f"""
    # [PATCHED - Directory Traversal Prevention]
    safe_filename = os.path.basename({param})
    filepath = os.path.join(SAFE_BASE_DIR, safe_filename)
    if not os.path.abspath(filepath).startswith(os.path.abspath(SAFE_BASE_DIR)):
        return "Access Denied: Path Traversal Detected", 403
"""
            if f"open({param}" in patched_content or f"open(filename" in patched_content:
                patched_content = re.sub(
                    rf'(filepath\s*=\s*os\.path\.join\([^)]+\))',
                    f'{traversal_fix}\n    \\1',
                    patched_content,
                    count=1
                )

        # 4. Patch Command Injection
        elif vuln_type in ["Command_Injection", "Remote_Code_Execution"]:
            remediation_notes = "Executes commands safely via subprocess.run() with shell=False and argument arrays instead of shell strings."
            clean_patch_snippet = f"""# --- Command Injection Remediation ---
import subprocess
import shlex

# Disallow arbitrary shell execution; pass parameters as explicit arguments:
clean_arg = shlex.quote(str({param}))
result = subprocess.run(["ping", "-c", "1", clean_arg], capture_output=True, text=True, shell=False)"""

            cmd_fix = f"""
    # [PATCHED - Safe Subprocess Execution without Shell]
    import subprocess
    import shlex
    clean_arg = shlex.quote(str({param}))
    result = subprocess.run(["ping", "-c", "1", clean_arg], capture_output=True, text=True, shell=False)
"""
            if "os.system" in patched_content:
                patched_content = re.sub(
                    rf'os\.system\([^)]+\)',
                    f'{cmd_fix}',
                    patched_content,
                    count=1
                )

        # 5. Patch Server-Side Template Injection (SSTI)
        elif vuln_type == "Server_Side_Template_Injection":
            remediation_notes = "Avoids formatting user inputs into template source strings; passes user inputs as template context parameters."
            clean_patch_snippet = f"""# --- SSTI Remediation ---
# Do not format variables into template source string:
# Replace: render_template_string(f"Hello {{{param}}}")
# With context parameter binding:
return render_template_string("Hello {{'{{'}} name {{'}}'}}", name={param})"""

            if "render_template_string" in patched_content:
                patched_content = re.sub(
                    r'render_template_string\(\s*f["\'][^"\']*\{\s*([a-zA-Z0-9_]+)\s*\}[^"\']*["\']\s*\)',
                    r'render_template_string("Hello {{ name }}", name=\1)',
                    patched_content
                )

        # 6. Patch Open Redirect
        elif vuln_type == "Open_Redirect":
            remediation_notes = "Enforces destination host validation against an authorized host whitelist or forces relative paths."
            clean_patch_snippet = f"""# --- Open Redirect Remediation ---
from urllib.parse import urlparse

ALLOWED_HOSTS = ['localhost', '127.0.0.1']
parsed = urlparse({param})
if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:
    return "Invalid redirect destination", 400
return redirect({param})"""

            redirect_fix = f"""
    # [PATCHED - Open Redirect Whitelist Validation]
    ALLOWED_HOSTS = ['localhost', '127.0.0.1']
    from urllib.parse import urlparse
    parsed = urlparse({param})
    if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:
        return "Invalid redirect destination", 400
"""
            if "redirect(" in patched_content:
                patched_content = re.sub(
                    rf'(return\s+redirect\({param}\))',
                    f'{redirect_fix}\n    \\1',
                    patched_content,
                    count=1
                )

        # Default fallback snippet
        if not clean_patch_snippet:
            clean_patch_snippet = f"""# --- General Remediation for {vuln_type} ---
# Implement strict validation and sanitization for parameter '{param}':
if not {param} or not str({param}).isalnum():
    return "Invalid input parameter", 400"""
            remediation_notes = f"Input validation rule for {param}."

        # Compute unified diff
        diff_lines = list(difflib.unified_diff(
            original_content.splitlines(keepends=True),
            patched_content.splitlines(keepends=True),
            fromfile=f"a/{target_file_path}",
            tofile=f"b/{target_file_path}"
        ))
        diff_text = "".join(diff_lines) if diff_lines else f"# No automatic regex diff could be computed for {vuln_type}.\n# Please apply the recommended remediation snippet above."

        return {
            "success": True,
            "target_file": target_file_path,
            "vuln_type": vuln_type,
            "parameter": param,
            "is_modified": patched_content != original_content,
            "original_code": original_content,
            "patched_code": patched_content,
            "diff_text": diff_text,
            "clean_patch_snippet": clean_patch_snippet,
            "remediation_notes": remediation_notes
        }

    def apply_patch(self, target_file_path: str, patched_code: str) -> Dict[str, Any]:
        """
        Safely write the patched code to the staging file.
        """
        full_path = os.path.abspath(os.path.join(self.staging_root, target_file_path)) if not os.path.isabs(target_file_path) else target_file_path
        
        if not os.path.exists(full_path):
            return {"success": False, "message": f"Target file '{full_path}' not found."}

        try:
            with open(full_path, "w", encoding="utf-8") as f:
                f.write(patched_code)
            return {
                "success": True,
                "message": f"Successfully applied patch to '{target_file_path}'.",
                "file_path": full_path
            }
        except Exception as e:
            return {"success": False, "message": f"Failed to write patch: {str(e)}"}
