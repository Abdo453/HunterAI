"""
Verifies Section 6 - Burp Extension contracts.
Causal chain: Extension exists -> AST contains required structure
"""
import ast
from pathlib import Path

def test_burp_extension_ast():
    ext_path = Path(__file__).resolve().parents[2] / "agents" / "burp_agent" / "integrations" / "burp_extension" / "hunter_burp_extension.py"
    assert ext_path.exists(), f"Burp extension not found: {ext_path}"
        
    with open(ext_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())
        
    classes = [node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    assert "BurpExtender" in classes
    
    methods = [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
    assert "processHttpMessage" in methods
    assert "registerExtenderCallbacks" in methods
