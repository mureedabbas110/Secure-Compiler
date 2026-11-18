import re
from security.risk_evaluator import calculate_risk_profile

def analyze_java_code(source_code):
    lines = source_code.splitlines()
    findings = []
    tokens = []
    symbols = []

    var_decl_pattern = re.compile(r'\b(int|String|char|boolean|double|float|long)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(=.*)?;')
    method_decl_pattern = re.compile(r'\b(public|private|protected)?\s*(static)?\s*([a-zA-Z0-9_<>]+)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')

    for i, line_text in enumerate(lines, start=1):
        clean = line_text.strip()
        if not clean or clean.startswith("//") or clean.startswith("/*"):
            continue

        m = method_decl_pattern.search(clean)
        if m:
            symbols.append({
                "name": m.group(4),
                "type": f"method -> {m.group(3)}",
                "scope": "class",
                "line": i,
                "init": True
            })

        v = var_decl_pattern.search(clean)
        if v:
            symbols.append({
                "name": v.group(2),
                "type": v.group(1),
                "scope": "local/member",
                "line": i,
                "init": bool(v.group(3))
            })

        # 1. Hardcoded Credentials
        cred_match = re.search(r'\b(password|secret|apiKey|api_key|token|key|pwd)\s*=\s*"([^"]+)"', clean, re.IGNORECASE)
        if cred_match:
            findings.append({
                "rule_id": "JAVA-001",
                "title": "Hardcoded Credential in Java Class",
                "severity": "MEDIUM",
                "line": i,
                "lexeme": cred_match.group(0),
                "evidence": clean,
                "description": f"Variable '{cred_match.group(1)}' is assigned a hardcoded literal credential in source code.",
                "recommendation": "Retrieve sensitive credentials from system properties or environment variables via System.getenv()."
            })

        # 2. Command Execution: Runtime.getRuntime().exec() or ProcessBuilder
        if "Runtime.getRuntime().exec(" in clean or "new ProcessBuilder(" in clean:
            match_word = "Runtime.getRuntime().exec" if "Runtime" in clean else "new ProcessBuilder"
            findings.append({
                "rule_id": "JAVA-002",
                "title": "Command Injection via Process Execution",
                "severity": "HIGH",
                "line": i,
                "lexeme": match_word,
                "evidence": clean,
                "description": "Calling external operating system processes allows command injection if parameters are tainted.",
                "recommendation": "Avoid invoking command shells directly, or strictly validate and sanitize all command arguments."
            })

        # 3. SQL Injection via string concatenation
        clean_upper = clean.upper()
        if "+" in clean and any(k in clean_upper for k in ['SELECT ', 'INSERT ', 'UPDATE ', 'DELETE ', 'WHERE ']):
            findings.append({
                "rule_id": "JAVA-003",
                "title": "SQL Injection Pattern via Concatenation",
                "severity": "HIGH",
                "line": i,
                "lexeme": "+ (SQL string concatenation)",
                "evidence": clean,
                "description": "Dynamically concatenated SQL string passed into database query execution method.",
                "recommendation": "Use PreparedStatement with parameter placeholders (?) rather than string concatenation."
            })

        # 4. Insecure Object Deserialization: ObjectInputStream.readObject()
        if ".readObject()" in clean or "new ObjectInputStream(" in clean:
            findings.append({
                "rule_id": "JAVA-004",
                "title": "Insecure Java Object Deserialization",
                "severity": "HIGH",
                "line": i,
                "lexeme": ".readObject()",
                "evidence": clean,
                "description": "Unrestricted object deserialization using ObjectInputStream can result in remote code execution (RCE).",
                "recommendation": "Avoid standard Java serialization; use JSON/Protobuf or implement ValidatingObjectInputStream."
            })

        # 5. Predictable Random Number Generation: java.util.Random
        if "new Random(" in clean:
            findings.append({
                "rule_id": "JAVA-005",
                "title": "Predictable Random Number Generator",
                "severity": "LOW",
                "line": i,
                "lexeme": "new Random()",
                "evidence": clean,
                "description": "java.util.Random produces deterministic pseudo-random sequences unsuited for cryptographic security.",
                "recommendation": "Use java.security.SecureRandom for security tokens, session identifiers, and keys."
            })

    for idx, l in enumerate(lines, start=1):
        words = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*|\d+|==|!=|<=|>=|[+\-*/=;{}()."]', l)
        for w in words:
            tokens.append({"type": "JAVA_LEXEME", "value": w, "line": idx})

    risk_profile = calculate_risk_profile(findings)
    ast_representation = {"type": "JavaCompilationUnit", "lines_analyzed": len(lines)}

    return {
        "success": True,
        "tokens": tokens,
        "ast": ast_representation,
        "symbols": symbols,
        "findings": findings,
        "risk_profile": risk_profile
    }
