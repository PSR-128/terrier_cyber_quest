import pytest
import os
import tempfile
from backend.patching.patch_engine import StagingPatchEngine

def test_patch_generation_and_application():
    engine = StagingPatchEngine()
    
    # Create temporary staging file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write('def search(username):\n    query = f"SELECT * FROM users WHERE username = \'{username}\'"\n    cursor.execute(query)\n')
        temp_path = f.name
        
    try:
        patch_res = engine.generate_patch(
            target_file_path=temp_path,
            vuln_type="SQL_Injection",
            parameter_name="username"
        )
        
        assert patch_res["success"] is True
        assert patch_res["is_modified"] is True
        assert "diff_text" in patch_res
        assert "clean_patch_snippet" in patch_res
        assert len(patch_res["clean_patch_snippet"]) > 0
        
        # Apply patch
        apply_res = engine.apply_patch(temp_path, patch_res["patched_code"])
        assert apply_res["success"] is True
        
        # Verify content was updated
        with open(temp_path, "r") as f:
            new_content = f.read()
        assert "SELECT * FROM users WHERE username = ?" in new_content or "PATCHED" in new_content
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
