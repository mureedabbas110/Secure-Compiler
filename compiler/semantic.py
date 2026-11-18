from compiler.ast_nodes import ASTNode

class Symbol:
    def __init__(self, name, data_type, scope, line, initialized=False, size=None):
        self.name = name
        self.data_type = data_type
        self.scope = scope
        self.line = line
        self.initialized = initialized
        self.size = size

class SymbolTable:
    def __init__(self):
        self.scopes = [{}]

    def enter_scope(self):
        self.scopes.append({})

    def exit_scope(self):
        if len(self.scopes) > 1:
            self.scopes.pop()

    def define(self, name, data_type, line, initialized=False, size=None):
        scope_name = f"scope_{len(self.scopes)}" if len(self.scopes) > 1 else "global"
        sym = Symbol(name, data_type, scope_name, line, initialized, size)
        self.scopes[-1][name] = sym
        return sym

    def resolve(self, name):
        for s in reversed(self.scopes):
            if name in s:
                return s[name]
        return None

class SemanticAnalyzer:
    def __init__(self):
        self.symbol_table = SymbolTable()
        self.flat_symbols = []
        self.errors = []

    def analyze(self, ast):
        self._visit(ast)
        return self.flat_symbols, self.errors

    def _visit(self, node):
        if not isinstance(node, ASTNode):
            return
        method_name = f"_visit_{node.node_type}"
        visitor = getattr(self, method_name, self._default_visit)
        visitor(node)

    def _default_visit(self, node):
        for _, attr in node.attributes.items():
            if isinstance(attr, ASTNode):
                self._visit(attr)
            elif isinstance(attr, list):
                for elem in attr:
                    if isinstance(elem, ASTNode):
                        self._visit(elem)

    def _visit_FuncDecl(self, node):
        fn_sym = self.symbol_table.define(node.name, f"func -> {node.return_type}", node.line, initialized=True)
        self.flat_symbols.append(fn_sym)
        self.symbol_table.enter_scope()
        for p in node.params:
            sym = self.symbol_table.define(p.name, p.data_type, p.line, initialized=True)
            self.flat_symbols.append(sym)
        self._visit(node.body)
        self.symbol_table.exit_scope()

    def _visit_MultiVarDecl(self, node):
        for decl in node.decls:
            self._visit(decl)

    def _visit_VarDecl(self, node):
        is_init = node.init is not None or node.data_type in ('string', 'std::string')
        sym = self.symbol_table.define(node.name, node.data_type, node.line, initialized=is_init, size=node.size)
        self.flat_symbols.append(sym)
        if node.init:
            self._visit(node.init)

    def _visit_AssignExpr(self, node):
        sym = self.symbol_table.resolve(node.target)
        if sym:
            sym.initialized = True
        self._visit(node.value)

    def _visit_CinStmt(self, node):
        for t in node.targets:
            sym = self.symbol_table.resolve(t)
            if sym:
                sym.initialized = True

    def _visit_GetlineStmt(self, node):
        sym = self.symbol_table.resolve(node.target)
        if sym:
            sym.initialized = True

    def _visit_CompoundStmt(self, node):
        self.symbol_table.enter_scope()
        for stmt in node.statements:
            self._visit(stmt)
        self.symbol_table.exit_scope()

    def _visit_ForStmt(self, node):
        self.symbol_table.enter_scope()
        if node.init:
            self._visit(node.init)
        if node.condition:
            self._visit(node.condition)
        if node.iter:
            self._visit(node.iter)
        if node.body:
            self._visit(node.body)
        self.symbol_table.exit_scope()
