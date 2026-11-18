import ast
from security.risk_evaluator import calculate_risk_profile

class PythonSecurityAnalyzer(ast.NodeVisitor):
    def __init__(self, source_code):
        self.source_lines = source_code.splitlines()
        self.findings = []
        self.tokens = []
        self.symbols = []

    def _get_line_text(self, line):
        if 1 <= line <= len(self.source_lines):
            return self.source_lines[line - 1].strip()
        return ""

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                name = target.id
                name_lower = name.lower()
                self.symbols.append({
                    "name": name,
                    "type": "variable",
                    "scope": "local/global",
                    "line": node.lineno,
                    "init": True
                })
                # Check for Hardcoded Credentials
                if any(k in name_lower for k in ['password', 'secret', 'api_key', 'token', 'key']):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        self.findings.append({
                            "rule_id": "PY-001",
                            "title": "Hardcoded Credential in Python Script",
                            "severity": "MEDIUM",
                            "line": node.lineno,
                            "lexeme": f"{name} = '{node.value.value}'",
                            "evidence": self._get_line_text(node.lineno),
                            "description": f"Identifier '{name}' contains hardcoded sensitive data.",
                            "recommendation": "Use os.environ.get('...') to read secrets securely from the environment."
                        })
        self.generic_visit(node)

    def visit_Call(self, node):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{func_name}"

        # 1. Arbitrary Code Execution: eval(), exec()
        if func_name in ['eval', 'exec']:
            self.findings.append({
                "rule_id": "PY-002",
                "title": "Arbitrary Code Execution via eval()/exec()",
                "severity": "HIGH",
                "line": node.lineno,
                "lexeme": f"{func_name}()",
                "evidence": self._get_line_text(node.lineno),
                "description": f"Dynamic execution with '{func_name}()' allows unvalidated strings to execute arbitrary code.",
                "recommendation": "Avoid eval/exec; use safe parsers like ast.literal_eval for structured data."
            })

        # 2. OS Command Injection: os.system(), subprocess.call(shell=True)
        if func_name in ['os.system', 'os.popen', 'subprocess.Popen', 'subprocess.call']:
            self.findings.append({
                "rule_id": "PY-003",
                "title": "Command Injection Risk in System Invocation",
                "severity": "HIGH",
                "line": node.lineno,
                "lexeme": f"{func_name}()",
                "evidence": self._get_line_text(node.lineno),
                "description": f"Invoking system shell via '{func_name}()' can permit command injection.",
                "recommendation": "Use subprocess.run(['cmd', 'arg1'], shell=False) with parameterized arguments."
            })

        # 3. Insecure Deserialization: pickle.loads()
        if func_name in ['pickle.loads', 'pickle.load']:
            self.findings.append({
                "rule_id": "PY-004",
                "title": "Insecure Deserialization via pickle",
                "severity": "HIGH",
                "line": node.lineno,
                "lexeme": f"{func_name}()",
                "evidence": self._get_line_text(node.lineno),
                "description": "Pickle serialization can execute arbitrary Python bytecode during unpickling.",
                "recommendation": "Use safe serialization formats such as JSON, Protocol Buffers, or cryptographic signatures."
            })

        # 4. Weak Pseudo-Random Number Generation: random.random()
        if func_name.startswith('random.') and not func_name.startswith('secrets.'):
            self.findings.append({
                "rule_id": "PY-005",
                "title": "Cryptographically Weak Pseudo-Random Generator",
                "severity": "LOW",
                "line": node.lineno,
                "lexeme": f"{func_name}()",
                "evidence": self._get_line_text(node.lineno),
                "description": "Standard Python 'random' module is not suitable for cryptographic tokens or security keys.",
                "recommendation": "Use the standard 'secrets' module for cryptographically secure randomness."
            })

        self.generic_visit(node)

    def visit_BinOp(self, node):
        if isinstance(node.op, (ast.Add, ast.Mod)):
            def has_sql(n):
                if isinstance(n, ast.Constant) and isinstance(n.value, str):
                    s = n.value.upper()
                    return any(w in s for w in ['SELECT ', 'INSERT ', 'UPDATE ', 'DELETE ', 'WHERE '])
                return False

            if has_sql(node.left) or has_sql(node.right):
                self.findings.append({
                    "rule_id": "PY-006",
                    "title": "SQL Injection Pattern via String Formatting",
                    "severity": "HIGH",
                    "line": node.lineno,
                    "lexeme": "% or + (SQL concatenation)",
                    "evidence": self._get_line_text(node.lineno),
                    "description": "SQL statement is being formatted directly with dynamic string concatenation.",
                    "recommendation": "Use parameterized query placeholders (?, %s) provided by DB-API."
                })
        self.generic_visit(node)

def analyze_python_code(source_code):
    try:
        parsed_ast = ast.parse(source_code)
    except SyntaxError as e:
        return {
            "success": False,
            "stage": "Python Syntax Analysis",
            "errors": [f"SyntaxError at line {e.lineno}: {e.msg} (near '{e.text.strip() if e.text else ''}')"]
        }

    import io, tokenize
    token_list = []
    try:
        tokens_gen = tokenize.generate_tokens(io.StringIO(source_code).readline)
        for tok in tokens_gen:
            if tok.type in (tokenize.COMMENT, tokenize.NL, tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER):
                continue
            token_list.append({
                "type": tokenize.tok_name.get(tok.type, 'TOKEN'),
                "value": tok.string,
                "line": tok.start[0]
            })
    except Exception:
        pass

    visitor = PythonSecurityAnalyzer(source_code)
    visitor.visit(parsed_ast)
    risk_profile = calculate_risk_profile(visitor.findings)
    ast_dict = {"type": "PythonModule", "body_count": len(parsed_ast.body)}

    return {
        "success": True,
        "tokens": token_list,
        "ast": ast_dict,
        "symbols": visitor.symbols,
        "findings": visitor.findings,
        "risk_profile": risk_profile
    }
