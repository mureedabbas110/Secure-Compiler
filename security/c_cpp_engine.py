from compiler.ast_nodes import ASTNode
from security.risk_evaluator import calculate_risk_profile

class CCppSecurityEngine:
    def __init__(self, ast, symbols, source_lines, is_cpp=False):
        self.ast = ast
        self.symbols = {s.name: s for s in symbols}
        self.source_lines = source_lines
        self.is_cpp = is_cpp
        self.findings = []
        self.assigned_vars = set()
        self.heap_allocations = []
        self.deallocations = set()

    def analyze(self):
        self._traverse(self.ast)
        self._check_memory_leaks()
        risk_profile = calculate_risk_profile(self.findings)
        return self.findings, risk_profile

    def _get_line_text(self, line):
        if 1 <= line <= len(self.source_lines):
            return self.source_lines[line - 1].strip()
        return ""

    def _traverse(self, node):
        if not isinstance(node, ASTNode):
            return

        if node.node_type == 'AssignExpr':
            self.assigned_vars.add(node.target)
            if hasattr(node, 'value') and isinstance(node.value, ASTNode) and node.value.node_type == 'NewExpr':
                self.heap_allocations.append((node.target, node.line))

        if node.node_type == 'VarDecl' and node.init:
            if isinstance(node.init, ASTNode) and node.init.node_type == 'NewExpr':
                self.heap_allocations.append((node.name, node.line))

        if node.node_type == 'DeleteStmt':
            self.deallocations.add(node.target)

        if node.node_type == 'CinStmt':
            for t in (node.targets or []):
                self.assigned_vars.add(t)

        if node.node_type == 'GetlineStmt' and node.target:
            self.assigned_vars.add(node.target)

        self._check_sec_001_and_006(node)
        self._check_sec_002(node)
        self._check_sec_003(node)
        self._check_sec_004(node)
        self._check_sec_005(node)

        for _, attr in node.attributes.items():
            if isinstance(attr, ASTNode):
                self._traverse(attr)
            elif isinstance(attr, list):
                for elem in attr:
                    if isinstance(elem, ASTNode):
                        self._traverse(elem)

    def _check_memory_leaks(self):
        for var_name, line in self.heap_allocations:
            if var_name not in self.deallocations:
                self.findings.append({
                    "rule_id": "CPP-001",
                    "title": "Potential Memory Leak (Missing delete)",
                    "severity": "MEDIUM",
                    "line": line,
                    "lexeme": f"new (assigned to {var_name})",
                    "evidence": self._get_line_text(line),
                    "description": f"Variable '{var_name}' is allocated dynamically via 'new' but has no corresponding 'delete' statement.",
                    "recommendation": f"Call 'delete {var_name};' before scope exit or use smart pointers (std::unique_ptr)."
                })

    def _check_sec_001_and_006(self, node):
        if node.node_type == 'FuncCall':
            fn = node.name
            evidence = self._get_line_text(node.line)
            if fn in ['gets', 'scanf']:
                self.findings.append({
                    "rule_id": "SEC-001",
                    "title": "Unsafe Input Function (Buffer Overflow Risk)",
                    "severity": "HIGH",
                    "line": node.line,
                    "lexeme": f"{fn}()",
                    "evidence": evidence,
                    "description": f"The '{fn}()' function reads input without guaranteed bounds checking, enabling buffer overflows.",
                    "recommendation": "Use bounded input mechanisms such as 'fgets(buf, sizeof(buf), stdin)' or std::cin with std::string."
                })
            elif fn in ['strcpy', 'sprintf', 'system']:
                self.findings.append({
                    "rule_id": "SEC-006",
                    "title": "Risky Function Usage",
                    "severity": "MEDIUM",
                    "line": node.line,
                    "lexeme": f"{fn}()",
                    "evidence": evidence,
                    "description": f"Invocation of '{fn}()' carries risks of memory corruption or arbitrary command execution.",
                    "recommendation": f"Use safer alternatives like 'strncpy', 'snprintf', or avoid direct system shell invocation."
                })

    def _check_sec_002(self, node):
        if node.node_type == 'FuncCall' and node.name in ['printf', 'fprintf', 'sprintf']:
            if len(node.args) >= 1:
                first_arg = node.args[0]
                if first_arg.node_type == 'Identifier':
                    self.findings.append({
                        "rule_id": "SEC-002",
                        "title": "Possible Format-String Misuse",
                        "severity": "HIGH",
                        "line": node.line,
                        "lexeme": f"{node.name}({first_arg.name})",
                        "evidence": self._get_line_text(node.line),
                        "description": f"Variable '{first_arg.name}' is passed directly as the format string parameter.",
                        "recommendation": f'Specify a constant format specifier: {node.name}("%s", {first_arg.name});'
                    })

    def _check_sec_003(self, node):
        suspicious_keywords = {'password', 'passwd', 'secret', 'token', 'api_key', 'apikey', 'key'}
        if node.node_type == 'VarDecl' and node.init:
            name_lower = node.name.lower()
            if any(k in name_lower for k in suspicious_keywords):
                if node.init.node_type == 'StringLiteral':
                    self.findings.append({
                        "rule_id": "SEC-003",
                        "title": "Hardcoded Credentials Detected",
                        "severity": "MEDIUM",
                        "line": node.line,
                        "lexeme": f'{node.name} = "{node.init.value}"',
                        "evidence": self._get_line_text(node.line),
                        "description": f"Identifier '{node.name}' matches sensitive key naming and stores a hardcoded literal value.",
                        "recommendation": "Read secret keys dynamically from external environment variables or a secret vault."
                    })

    def _check_sec_004(self, node):
        if node.node_type == 'BinaryExpr' and node.op == '+':
            def find_sql_fragments(curr_node):
                if not isinstance(curr_node, ASTNode):
                    return False
                if curr_node.node_type == 'StringLiteral':
                    val = curr_node.value.upper()
                    if any(kw in val for kw in ['SELECT ', 'INSERT ', 'UPDATE ', 'DELETE ', 'WHERE ']):
                        return True
                return any(find_sql_fragments(c) for c in curr_node.attributes.values() if isinstance(c, ASTNode))

            if find_sql_fragments(node):
                self.findings.append({
                    "rule_id": "SEC-004",
                    "title": "Potential SQL Injection Pattern",
                    "severity": "HIGH",
                    "line": node.line,
                    "lexeme": "+ (SQL string concatenation)",
                    "evidence": self._get_line_text(node.line),
                    "description": "SQL query expression is being constructed via dynamic string concatenation.",
                    "recommendation": "Use parameterized queries or prepared statements instead of string concatenation."
                })

    def _check_sec_005(self, node):
        if node.node_type == 'Identifier':
            sym = self.symbols.get(node.name)
            if sym and not sym.initialized and node.name not in self.assigned_vars:
                if not sym.data_type.startswith('func') and not sym.data_type.endswith('[]') and sym.size is None and sym.data_type not in ('string', 'std::string'):
                    self.findings.append({
                        "rule_id": "SEC-005",
                        "title": "Possible Uninitialized-Variable Read",
                        "severity": "MEDIUM",
                        "line": node.line,
                        "lexeme": node.name,
                        "evidence": self._get_line_text(node.line),
                        "description": f"Variable '{node.name}' is accessed before any assignment initializes its memory.",
                        "recommendation": f"Explicitly initialize '{node.name}' at its declaration site."
                    })
