from pathlib import Path


def test_compose_bindings():
    path = Path("docker-compose.yml")
    if not path.exists():
        return
    
    content = path.read_text()
    
    # Require specific exact port mappings
    assert '"127.0.0.1:8080:8080"' in content
    assert '"127.0.0.1:9001:9001"' in content
    assert '"127.0.0.1:9002:9002"' in content
    
    # Must not contain bad configurations
    assert "privileged:" not in content
    assert "docker.sock" not in content
    assert "network_mode:" not in content
    assert "network_mode: host" not in content
    assert "0.0.0.0" not in content
    
    # Security options required
    assert "cap_drop:" in content
    assert "read_only: true" in content
    assert "no-new-privileges:true" in content
    
    # Ensure all exposed ports are on 127.0.0.1
    for line in content.splitlines():
        line = line.strip()
        # if it looks like a port mapping...
        if line.startswith("-") and ":" in line and '"' in line:
            if "127.0.0.1:" in line:
                continue
            if line.count(":") == 1 and line.split(":")[0].strip('- "').isdigit():
                # this is something like "8080:8080"
                raise AssertionError(f"Port mapped without 127.0.0.1 bound: {line}")
