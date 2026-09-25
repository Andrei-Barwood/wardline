from pathlib import Path
import re

def test_threat_model_shape():
    path = Path("docs/threat-model.md")
    assert path.exists(), "Threat model file does not exist"
    
    content = path.read_text(encoding="utf-8")
    
    # Check for the nine threat titles (H2)
    expected_threats = [
        "## Abuso de autenticación",
        "## Abuso de autorización",
        "## Flooding de peticiones",
        "## Entrada mal formada",
        "## Mensajes de tamaño excesivo",
        "## Agotamiento de conexiones TCP",
        "## Ráfagas UDP",
        "## Inundación de logs",
        "## Agotamiento de recursos del proceso",
    ]
    for threat in expected_threats:
        assert threat in content, f"Missing threat title: {threat}"
        
    # Check for headers inside the sections
    required_labels = ["Attack surface", "Impact", "Detection", "Mitigation", "Recovery"]
    for label in required_labels:
        # We check that the label appears 9 times (once per threat)
        # Using count to verify rough shape
        assert content.count(f"**{label}**") >= 9 or content.count(f"{label}:") >= 9 or content.count(label) >= 9, f"Missing {label} in threat model"
        
    # Check for the 10 principles
    expected_principles = [
        "least privilege",
        "defense in depth",
        "secure defaults",
        "fail safely",
        "input validation",
        "explicit authorization",
        "observability",
        "auditability",
        "graceful degradation",
        "recovery"
    ]
    for principle in expected_principles:
        assert principle in content or f"**{principle}**" in content, f"Missing principle: {principle}"
        
    # Prohibited words
    prohibited = ["metasploit", "nmap", "shellcode", "iptables"]
    content_lower = content.lower()
    for word in prohibited:
        assert word not in content_lower, f"Prohibited word found: {word}"
        
    # Requires inprocess
    assert "inprocess" in content, "Missing 'inprocess' reference"
    
    # Verify that the detected event types (inside backticks) starting with specific prefixes are found in src/
    event_types = set()
    for match in re.finditer(r'`(security_[a-z_]+|anomaly_[a-z_]+|simulated_[a-z_]+)`', content):
        event_types.add(match.group(1))
        
    assert len(event_types) > 0, "No event types found in detection sections"
    
    # We should scan src/ to see if the string literally exists in .py files
    src_dir = Path("src")
    py_files = list(src_dir.rglob("*.py"))
    
    for etype in event_types:
        found = False
        for fpath in py_files:
            if etype in fpath.read_text(encoding="utf-8"):
                found = True
                break
        assert found, f"Event type '{etype}' not found in any source file in src/"
