from pathlib import Path


def test_workflow_file_exists_and_is_restrictive():
    path = Path(".github/workflows/tests.yml")
    if not path.exists():
        raise AssertionError("Workflow file not found")
        
    content = path.read_text()
    
    # Required tools and versions
    assert '"3.12"' in content or "'3.12'" in content or "3.12" in content
    assert '"3.13"' in content or "'3.13'" in content or "3.13" in content
    assert "ruff check src tests" in content
    assert "mypy src" in content
    assert "pytest" in content
    assert "--cov-fail-under=70" in content
    
    # Required security permissions
    assert "permissions:" in content
    
    # We expect precisely "permissions:\\n  contents: read"
    # Check that there are no other permissions.
    lines = content.splitlines()
    perm_idx = -1
    for i, line in enumerate(lines):
        if line.startswith("permissions:"):
            perm_idx = i
            break
            
    assert perm_idx != -1
    assert lines[perm_idx + 1].strip() == "contents: read"
    
    # Excluded keywords
    forbidden = ["pull_request_target", "docker login", "aws", "pypi", "secrets."]
    for f in forbidden:
        assert f not in content, f"Forbidden keyword found: {f}"
