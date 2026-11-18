import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from app import run_pipeline

def test_c_analysis_and_lexemes():
    code = """
    int main() {
        char buffer[64];
        gets(buffer);
        printf(buffer);
        return 0;
    }
    """
    res = run_pipeline(code, language="c")
    assert res["success"] is True
    assert res["language"] == "C"
    findings = res["findings"]
    assert any(f["rule_id"] == "SEC-001" and "gets" in f["lexeme"] for f in findings)
    assert any(f["rule_id"] == "SEC-002" for f in findings)
    assert res["risk_profile"]["score"] >= 60

def test_cpp_memory_leak():
    code = """
    int main() {
        char buffer[64];
        int leak = new int;
        gets(buffer);
        return 0;
    }
    """
    res = run_pipeline(code, language="cpp")
    assert res["success"] is True
    assert res["language"] == "C++"
    assert any(f["rule_id"] == "CPP-001" for f in res["findings"])

def test_python_vulnerabilities():
    code = """
import os
api_key = "super_secret_python_key"
os.system("ls")
eval("1 + 1")
    """
    res = run_pipeline(code, language="python")
    assert res["success"] is True
    assert res["language"] == "Python"
    rule_ids = [f["rule_id"] for f in res["findings"]]
    assert "PY-001" in rule_ids
    assert "PY-002" in rule_ids
    assert "PY-003" in rule_ids
    assert res["risk_profile"]["score"] >= 75

def test_java_vulnerabilities():
    code = """
public class Test {
    public static void main(String[] args) {
        String password = "admin_secret_java";
        Runtime.getRuntime().exec("whoami");
        String sql = "SELECT * FROM users WHERE id = " + args[0];
    }
}
    """
    res = run_pipeline(code, language="java")
    assert res["success"] is True
    assert res["language"] == "Java"
    rule_ids = [f["rule_id"] for f in res["findings"]]
    assert "JAVA-001" in rule_ids
    assert "JAVA-002" in rule_ids
    assert "JAVA-003" in rule_ids
    assert res["risk_profile"]["score"] >= 60

def test_clean_python_code():
    code = """
def add(a, b):
    return a + b
result = add(10, 20)
print(result)
    """
    res = run_pipeline(code, language="python")
    assert res["success"] is True
    assert len(res["findings"]) == 0
    assert res["risk_profile"]["score"] == 0

def test_missing_language_prompt():
    code = "int x = 10;"
    res = run_pipeline(code, language=None)
    assert res["success"] is False
    assert res["stage"] == "Language Selection"
