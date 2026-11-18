"""
Secure Compiler - Clean High-to-High Transcompiler Engine
Translates source code cleanly between C, C++, Python, and Java.
Produces clean, readable, runnable target programs across all 4 languages.
"""
import ast
import re

def get_all_conversions(source_code, source_lang):
    langs = ["c", "cpp", "python", "java"]
    return {target: transcompile(source_code, source_lang, target) for target in langs}

def transcompile(source_code, from_lang, to_lang):
    from_l = from_lang.lower().strip()
    to_l = to_lang.lower().strip()
    if to_l in ['cpp', 'c++']: to_l = 'cpp'
    if from_l in ['cpp', 'c++']: from_l = 'cpp'

    if from_l == to_l:
        return source_code.strip()

    if from_l == 'python':
        return _transcompile_from_python(source_code, to_l)
    else:
        return _transcompile_from_c_family(source_code, from_l, to_l)


# ==============================================================================
# PART 1: PYTHON -> C / C++ / JAVA (AST-Driven Clean Code Generation)
# ==============================================================================

class _PyToTargetVisitor(ast.NodeVisitor):
    def __init__(self, target_lang):
        self.target = target_lang
        self.functions = []
        self.var_types = {}
        self.has_input = False

    def _extract_input_call(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == 'input':
                prompt = self._expr(node.args[0]) if node.args else None
                return ('String', prompt)
            if node.func.id in ('int', 'float') and len(node.args) == 1:
                inner = node.args[0]
                if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name) and inner.func.id == 'input':
                    prompt = self._expr(inner.args[0]) if inner.args else None
                    t = 'int' if node.func.id == 'int' else 'double'
                    return (t, prompt)
        return None

    def _infer_type(self, node):
        if isinstance(node, ast.Constant):
            if isinstance(node.value, bool): return 'bool'
            if isinstance(node.value, int): return 'int'
            if isinstance(node.value, float): return 'double'
            if isinstance(node.value, str): return 'String'
        if isinstance(node, ast.BinOp):
            lt = self._infer_type(node.left)
            rt = self._infer_type(node.right)
            if lt == 'String' or rt == 'String': return 'String'
            if lt == 'double' or rt == 'double': return 'double'
            return 'int'
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id == 'input': return 'String'
                if node.func.id == 'int': return 'int'
                if node.func.id == 'float': return 'double'
                if node.func.id == 'str': return 'String'
        if isinstance(node, ast.Name) and node.id in self.var_types:
            return self.var_types[node.id]
        return 'int'

    def _map_type(self, inferred):
        if self.target == 'c':
            return {'int': 'int', 'double': 'double', 'bool': 'int', 'String': 'const char*'}.get(inferred, 'int')
        elif self.target == 'cpp':
            return {'int': 'int', 'double': 'double', 'bool': 'bool', 'String': 'string'}.get(inferred, 'int')
        elif self.target == 'java':
            return {'int': 'int', 'double': 'double', 'bool': 'boolean', 'String': 'String'}.get(inferred, 'int')
        return 'int'

    def _expr(self, node):
        if node is None:
            return ""
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                escaped = node.value.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
                return f'"{escaped}"'
            if isinstance(node.value, bool):
                if self.target == 'c': return "1" if node.value else "0"
                return "true" if node.value else "false"
            if node.value is None:
                return "NULL" if self.target in ['c', 'cpp'] else "null"
            return str(node.value)
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.BinOp):
            left = self._expr(node.left)
            right = self._expr(node.right)
            op_map = {
                ast.Add: '+', ast.Sub: '-', ast.Mult: '*', ast.Div: '/',
                ast.Mod: '%', ast.FloorDiv: '/'
            }
            op = op_map.get(type(node.op), '+')
            if isinstance(node.op, ast.Add) and self.target == 'c':
                lt = self._infer_type(node.left)
                rt = self._infer_type(node.right)
                if lt == 'String' or rt == 'String':
                    return f'{left} /* + {right} */'
            return f"{left} {op} {right}"
        if isinstance(node, ast.UnaryOp):
            operand = self._expr(node.operand)
            if isinstance(node.op, ast.USub): return f"-{operand}"
            if isinstance(node.op, ast.Not): return f"!({operand})"
            return operand
        if isinstance(node, ast.Compare):
            left = self._expr(node.left)
            parts = [left]
            cmp_map = {
                ast.Eq: '==', ast.NotEq: '!=', ast.Lt: '<',
                ast.LtE: '<=', ast.Gt: '>', ast.GtE: '>='
            }
            for op, comp in zip(node.ops, node.comparators):
                parts.append(cmp_map.get(type(op), '=='))
                parts.append(self._expr(comp))
            return " ".join(parts)
        if isinstance(node, ast.BoolOp):
            op_str = " && " if isinstance(node.op, ast.And) else " || "
            return op_str.join(self._expr(v) for v in node.values)
        if isinstance(node, ast.JoinedStr):
            pieces = []
            for v in node.values:
                if isinstance(v, ast.Constant):
                    pieces.append(f'"{v.value}"')
                elif isinstance(v, ast.FormattedValue):
                    pieces.append(self._expr(v.value))
            if self.target in ['java', 'cpp']:
                return ' + '.join(pieces)
            return "".join(pieces)
        if isinstance(node, ast.Call):
            fn_name = ""
            if isinstance(node.func, ast.Name):
                fn_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    fn_name = f"{node.func.value.id}.{node.func.attr}"
                else:
                    fn_name = node.func.attr

            args = [self._expr(a) for a in node.args]
            if fn_name in ['int', 'float', 'str', 'bool'] and args:
                return args[0]
            if fn_name == 'len' and args:
                if self.target == 'c': return f"strlen({args[0]})"
                return f"{args[0]}.length()"
            if fn_name == 'os.system' and args:
                if self.target in ['c', 'cpp']: return f"system({args[0]})"
                if self.target == 'java': return f"Runtime.getRuntime().exec({args[0]})"
            if fn_name == 'eval' and args:
                return f"// Dynamic eval skipped: {args[0]}"
            return f"{fn_name}({', '.join(args)})"
        if isinstance(node, ast.Subscript):
            val = self._expr(node.value)
            sl = self._expr(node.slice)
            return f"{val}[{sl}]"
        return "0"

    def _emit_input_assignment(self, name, input_type, prompt, pad):
        self.has_input = True
        is_new = name not in self.var_types
        self.var_types[name] = input_type
        out = []

        if self.target == 'c':
            if input_type == 'int':
                if is_new:
                    out.append(f"{pad}int {name};")
                if prompt:
                    out.append(f"{pad}printf({prompt});")
                out.append(f'{pad}scanf("%d", &{name});')
            elif input_type == 'double':
                if is_new:
                    out.append(f"{pad}double {name};")
                if prompt:
                    out.append(f"{pad}printf({prompt});")
                out.append(f'{pad}scanf("%lf", &{name});')
            else:
                if is_new:
                    out.append(f"{pad}char {name}[128];")
                if prompt:
                    out.append(f"{pad}printf({prompt});")
                out.append(f"{pad}fgets({name}, sizeof({name}), stdin);")

        elif self.target == 'cpp':
            if input_type == 'int':
                if is_new:
                    out.append(f"{pad}int {name};")
                if prompt:
                    out.append(f"{pad}cout << {prompt};")
                out.append(f"{pad}cin >> {name};")
            elif input_type == 'double':
                if is_new:
                    out.append(f"{pad}double {name};")
                if prompt:
                    out.append(f"{pad}cout << {prompt};")
                out.append(f"{pad}cin >> {name};")
            else:
                if is_new:
                    out.append(f"{pad}string {name};")
                if prompt:
                    out.append(f"{pad}cout << {prompt};")
                out.append(f"{pad}getline(cin, {name});")

        elif self.target == 'java':
            if prompt:
                out.append(f"{pad}System.out.print({prompt});")
            prefix = ""
            if input_type == 'int':
                prefix = "int " if is_new else ""
                out.append(f"{pad}{prefix}{name} = scanner.nextInt();")
            elif input_type == 'double':
                prefix = "double " if is_new else ""
                out.append(f"{pad}{prefix}{name} = scanner.nextDouble();")
            else:
                prefix = "String " if is_new else ""
                out.append(f"{pad}{prefix}{name} = scanner.nextLine();")

        return out

    def _convert_stmt_list(self, stmts, indent_level=1):
        lines = []
        pad = "    " * indent_level
        for stmt in stmts:
            if isinstance(stmt, (ast.Import, ast.ImportFrom, ast.Pass)):
                continue
            elif isinstance(stmt, ast.Assign):
                if len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                    name = stmt.targets[0].id
                    inp_info = self._extract_input_call(stmt.value)
                    if inp_info is not None:
                        input_type, prompt = inp_info
                        lines.extend(self._emit_input_assignment(name, input_type, prompt, pad))
                        continue

                    inferred = self._infer_type(stmt.value)
                    expr_str = self._expr(stmt.value)
                    if name not in self.var_types:
                        self.var_types[name] = inferred
                        t_str = self._map_type(inferred)
                        lines.append(f"{pad}{t_str} {name} = {expr_str};")
                    else:
                        lines.append(f"{pad}{name} = {expr_str};")

            elif isinstance(stmt, ast.AugAssign):
                target = self._expr(stmt.target)
                val = self._expr(stmt.value)
                op_map = {ast.Add: '+=', ast.Sub: '-=', ast.Mult: '*=', ast.Div: '/=', ast.Mod: '%='}
                op = op_map.get(type(stmt.op), '+=')
                lines.append(f"{pad}{target} {op} {val};")

            elif isinstance(stmt, ast.Expr):
                if isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Name) and stmt.value.func.id == 'print':
                    lines.extend(self._format_print(stmt.value, pad))
                else:
                    expr_str = self._expr(stmt.value)
                    if expr_str:
                        if expr_str.startswith('//'):
                            lines.append(f"{pad}{expr_str}")
                        else:
                            lines.append(f"{pad}{expr_str};")

            elif isinstance(stmt, ast.Return):
                val = self._expr(stmt.value) if stmt.value else ""
                lines.append(f"{pad}return {val};" if val else f"{pad}return;")

            elif isinstance(stmt, ast.If):
                if isinstance(stmt.test, ast.Compare) and isinstance(stmt.test.left, ast.Name) and stmt.test.left.id == '__name__':
                    continue
                cond = self._expr(stmt.test)
                lines.append(f"{pad}if ({cond}) {{")
                lines.extend(self._convert_stmt_list(stmt.body, indent_level + 1))
                if stmt.orelse:
                    if len(stmt.orelse) == 1 and isinstance(stmt.orelse[0], ast.If):
                        sub_if = self._convert_stmt_list(stmt.orelse, indent_level)
                        if sub_if:
                            sub_if[0] = f"{pad}}} else " + sub_if[0].lstrip()
                            lines.extend(sub_if)
                    else:
                        lines.append(f"{pad}}} else {{")
                        lines.extend(self._convert_stmt_list(stmt.orelse, indent_level + 1))
                        lines.append(f"{pad}}}")
                else:
                    lines.append(f"{pad}}}")

            elif isinstance(stmt, ast.While):
                cond = self._expr(stmt.test)
                lines.append(f"{pad}while ({cond}) {{")
                lines.extend(self._convert_stmt_list(stmt.body, indent_level + 1))
                lines.append(f"{pad}}}")

            elif isinstance(stmt, ast.For):
                if isinstance(stmt.target, ast.Name) and isinstance(stmt.iter, ast.Call) and isinstance(stmt.iter.func, ast.Name) and stmt.iter.func.id == 'range':
                    var = stmt.target.id
                    self.var_types[var] = 'int'
                    r_args = [self._expr(a) for a in stmt.iter.args]
                    if len(r_args) == 1:
                        start, end, step = "0", r_args[0], "1"
                    elif len(r_args) == 2:
                        start, end, step = r_args[0], r_args[1], "1"
                    else:
                        start, end, step = r_args[0], r_args[1], r_args[2]
                    inc = f"{var}++" if step == "1" else f"{var} += {step}"
                    lines.append(f"{pad}for (int {var} = {start}; {var} < {end}; {inc}) {{")
                    lines.extend(self._convert_stmt_list(stmt.body, indent_level + 1))
                    lines.append(f"{pad}}}")

            elif isinstance(stmt, ast.FunctionDef):
                saved_vars = dict(self.var_types)
                self.var_types = {}
                params = []
                for arg in stmt.args.args:
                    p_type = self._map_type('int')
                    if arg.annotation and isinstance(arg.annotation, ast.Name):
                        ann = arg.annotation.id
                        if ann == 'str': p_type = self._map_type('String')
                        elif ann == 'float': p_type = self._map_type('double')
                        elif ann == 'bool': p_type = self._map_type('bool')
                    self.var_types[arg.arg] = 'int'
                    params.append(f"{p_type} {arg.arg}")

                has_ret = any(isinstance(n, ast.Return) and n.value is not None for n in ast.walk(stmt))
                ret_t = self._map_type('int') if has_ret else "void"

                fn_body = self._convert_stmt_list(stmt.body, 2 if self.target == 'java' else 1)
                self.functions.append({
                    'name': stmt.name,
                    'ret_type': ret_t,
                    'params': ", ".join(params),
                    'body': fn_body
                })
                self.var_types = saved_vars

        return lines

    def _format_print(self, call_node, pad):
        if not call_node.args:
            if self.target == 'c': return [f'{pad}printf("\\n");']
            if self.target == 'cpp': return [f'{pad}cout << endl;']
            if self.target == 'java': return [f'{pad}System.out.println();']

        arg0 = call_node.args[0]
        if isinstance(arg0, ast.JoinedStr):
            if self.target == 'c':
                fmt_parts = []
                c_args = []
                for v in arg0.values:
                    if isinstance(v, ast.Constant):
                        fmt_parts.append(str(v.value).replace('%', '%%'))
                    elif isinstance(v, ast.FormattedValue):
                        t = self._infer_type(v.value)
                        fmt_parts.append('%s' if t == 'String' else ('%f' if t == 'double' else '%d'))
                        c_args.append(self._expr(v.value))
                fmt_str = "".join(fmt_parts)
                if c_args:
                    return [f'{pad}printf("{fmt_str}\\n", {", ".join(c_args)});']
                return [f'{pad}printf("{fmt_str}\\n");']
            elif self.target == 'cpp':
                cpp_parts = []
                for v in arg0.values:
                    if isinstance(v, ast.Constant) and v.value != "":
                        cpp_parts.append(f'"{v.value}"')
                    elif isinstance(v, ast.FormattedValue):
                        cpp_parts.append(self._expr(v.value))
                return [f'{pad}cout << {" << ".join(cpp_parts)} << endl;']
            elif self.target == 'java':
                j_parts = []
                for v in arg0.values:
                    if isinstance(v, ast.Constant) and v.value != "":
                        j_parts.append(f'"{v.value}"')
                    elif isinstance(v, ast.FormattedValue):
                        j_parts.append(self._expr(v.value))
                return [f'{pad}System.out.println({" + ".join(j_parts)});']

        args_expr = [self._expr(a) for a in call_node.args]
        if self.target == 'c':
            if len(args_expr) == 1:
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                    escaped = arg0.value.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
                    return [f'{pad}printf("{escaped}\\n");']
                t = self._infer_type(arg0)
                spec = '%s' if t == 'String' else ('%f' if t == 'double' else '%d')
                return [f'{pad}printf("{spec}\\n", {args_expr[0]});']
            fmt = " ".join('%s' if self._infer_type(a) == 'String' else '%d' for a in call_node.args)
            return [f'{pad}printf("{fmt}\\n", {", ".join(args_expr)});']
        elif self.target == 'cpp':
            joined = ' << " " << '.join(args_expr)
            return [f'{pad}cout << {joined} << endl;']
        elif self.target == 'java':
            joined = ' + " " + '.join(args_expr)
            return [f'{pad}System.out.println({joined});']
        return []

def _transcompile_from_python(source_code, target_lang):
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return source_code

    visitor = _PyToTargetVisitor(target_lang)
    main_body = visitor._convert_stmt_list(tree.body, 2 if target_lang == 'java' else 1)

    explicit_main = next((f for f in visitor.functions if f['name'] == 'main'), None)
    helper_funcs = [f for f in visitor.functions if f['name'] != 'main']

    if target_lang == 'c':
        out = ['#include <stdio.h>', '#include <stdlib.h>', '#include <string.h>', '']
        for fn in helper_funcs:
            out.append(f"{fn['ret_type']} {fn['name']}({fn['params']}) {{")
            out.extend(fn['body'])
            out.append("}\n")
        out.append("int main() {")
        body_lines = explicit_main['body'] if explicit_main else main_body
        out.extend(body_lines)
        if not any('return ' in l for l in body_lines):
            out.append("    return 0;")
        out.append("}")
        return "\n".join(out)

    elif target_lang == 'cpp':
        out = ['#include <iostream>', '#include <string>', '', 'using namespace std;', '']
        for fn in helper_funcs:
            out.append(f"{fn['ret_type']} {fn['name']}({fn['params']}) {{")
            out.extend(fn['body'])
            out.append("}\n")
        out.append("int main() {")
        body_lines = explicit_main['body'] if explicit_main else main_body
        out.extend(body_lines)
        if not any('return ' in l for l in body_lines):
            out.append("    return 0;")
        out.append("}")
        return "\n".join(out)

    elif target_lang == 'java':
        out = []
        if visitor.has_input:
            out.append('import java.util.Scanner;\n')
        out.append('public class Main {')
        if visitor.has_input:
            out.append('    private static Scanner scanner = new Scanner(System.in);\n')
        for fn in helper_funcs:
            out.append(f"    public static {fn['ret_type']} {fn['name']}({fn['params']}) {{")
            out.extend(fn['body'])
            out.append("    }\n")
        out.append("    public static void main(String[] args) {")
        body_to_use = explicit_main['body'] if explicit_main else main_body
        for line in body_to_use:
            if not line.strip().startswith('return '):
                out.append(line)
        out.append("    }")
        out.append("}")
        return "\n".join(out)

    return source_code


# ==============================================================================
# PART 2: C / C++ / JAVA -> PYTHON / JAVA / C++ / C (Clean Block Parser)
# ==============================================================================

def _transcompile_from_c_family(source_code, from_lang, to_lang):
    lines = source_code.splitlines()
    functions = []
    curr_func = None
    brace_depth = 0
    scanner_vars = set()

    for raw in lines:
        s = raw.strip()
        if '//' in s and not ('"//' in s or "'//" in s):
            s = s.split('//')[0].strip()
        if not s or s.startswith(('#include', 'import ', 'package ', 'using namespace', '/*')):
            continue

        # Track Scanner variable names (e.g., `Scanner input = new Scanner(System.in);`)
        sc_m = re.match(r'^Scanner\s+([a-zA-Z0-9_]+)\s*=\s*new\s+Scanner', s)
        if sc_m:
            scanner_vars.add(sc_m.group(1))
            continue

        if re.match(r'^(?:public\s+)?class\s+[a-zA-Z0-9_]+\s*\{?$', s):
            continue

        if curr_func is None:
            if s in ['{', '}']:
                continue
            m = re.match(
                r'^(?:(?:public|private|protected|static|inline|virtual|final)\s+)*'
                r'(?:(?:const\s+)?([a-zA-Z0-9_<>\[\]*]+)\s+)?'
                r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*(?:const)?\s*\{?$',
                s
            )
            if m and m.group(2) not in ['if', 'while', 'for', 'switch', 'printf', 'scanf', 'gets', 'strcpy', 'return', 'else', 'catch', 'System']:
                ret_type = m.group(1) or 'int'
                fn_name = m.group(2)
                raw_params = m.group(3).strip()
                params = []
                if raw_params and raw_params != 'void' and 'String[]' not in raw_params:
                    for p in raw_params.split(','):
                        parts = p.strip().split()
                        if len(parts) >= 2:
                            p_type = ' '.join(parts[:-1])
                            p_name = parts[-1].lstrip('*&')
                            params.append({'type': p_type, 'name': p_name})
                        elif len(parts) == 1:
                            params.append({'type': 'int', 'name': parts[0]})
                curr_func = {
                    'ret_type': ret_type,
                    'name': fn_name,
                    'params': params,
                    'raw_lines': [],
                    'is_main': (fn_name == 'main')
                }
                brace_depth = s.count('{') - s.count('}')
                continue
        else:
            brace_depth += s.count('{') - s.count('}')
            if brace_depth <= 0 and '}' in s:
                before_brace = s.split('}')[0].strip()
                if before_brace:
                    curr_func['raw_lines'].append(before_brace)
                functions.append(curr_func)
                curr_func = None
                brace_depth = 0
            else:
                curr_func['raw_lines'].append(s)

    if curr_func:
        functions.append(curr_func)

    if not functions:
        body = [l.strip() for l in lines if l.strip() and not l.strip().startswith(('#', 'import ', '//'))]
        functions.append({'ret_type': 'int', 'name': 'main', 'params': [], 'raw_lines': body, 'is_main': True})

    if to_lang == 'python':
        return _emit_python(functions, scanner_vars)
    elif to_lang == 'java':
        return _emit_java(functions, scanner_vars)
    elif to_lang == 'cpp':
        return _emit_cpp(functions, scanner_vars)
    elif to_lang == 'c':
        return _emit_c(functions, scanner_vars)
    return source_code

def _normalize_c_type(t, target_lang):
    base = t.replace('*', '').replace('&', '').strip()
    if target_lang == 'java':
        return {'int': 'int', 'char': 'String' if '*' in t else 'char', 'float': 'float',
                'double': 'double', 'bool': 'boolean', 'boolean': 'boolean', 'String': 'String',
                'string': 'String', 'std::string': 'String', 'void': 'void'}.get(base, 'int')
    elif target_lang == 'cpp':
        return {'int': 'int', 'char': 'string' if '*' in t else 'char', 'float': 'float',
                'double': 'double', 'bool': 'bool', 'boolean': 'bool', 'String': 'string',
                'string': 'string', 'std::string': 'string', 'void': 'void'}.get(base, 'int')
    elif target_lang == 'c':
        return {'int': 'int', 'char': 'char*' if '*' in t else 'char', 'float': 'float',
                'double': 'double', 'bool': 'int', 'boolean': 'int', 'String': 'const char*',
                'string': 'const char*', 'std::string': 'const char*', 'void': 'void'}.get(base, 'int')
    return 'int'

def _is_scanner_noise(line, scanner_vars):
    s = line.rstrip(';').strip()
    if 'new Scanner' in s:
        return True
    for sv in scanner_vars:
        if s == f"{sv}.close()":
            return True
    if re.match(r'^[a-zA-Z0-9_]+\.close\(\)$', s):
        return True
    return False

def _emit_python(functions, scanner_vars=None):
    scanner_vars = scanner_vars or set()
    out = []
    for fn in functions:
        p_str = ", ".join(p['name'] for p in fn['params'])
        out.append(f"def {fn['name']}({p_str}):")
        indent = 1
        emitted_count = 0

        for raw in fn['raw_lines']:
            s = raw.strip()
            if not s or _is_scanner_noise(s, scanner_vars):
                continue

            while s.startswith('}'):
                indent = max(1, indent - 1)
                s = s[1:].strip()

            if not s or s == '{':
                continue

            has_open_brace = s.endswith('{')
            if has_open_brace:
                s = s[:-1].strip()
            s = s.rstrip(';').strip()

            pad = "    " * indent
            py_line = _stmt_to_python(s)
            if py_line:
                out.append(f"{pad}{py_line}")
                emitted_count += 1
                if py_line.endswith(':') or has_open_brace:
                    indent += 1

        if emitted_count == 0:
            out.append("    pass")
        out.append("")

    if any(f['is_main'] for f in functions):
        out.append('if __name__ == "__main__":')
        out.append('    main()')

    return "\n".join(out).strip()

def _stmt_to_python(s):
    if not s:
        return None

    if s.startswith('else if'):
        m = re.match(r'else\s+if\s*\((.+)\)', s)
        return f"elif {_expr_to_py(m.group(1))}:" if m else "elif True:"
    if s.startswith('if'):
        m = re.match(r'if\s*\((.+)\)', s)
        return f"if {_expr_to_py(m.group(1))}:" if m else "if True:"
    if s == 'else':
        return "else:"

    m_for = re.match(r'for\s*\(\s*(?:(?:int|size_t|auto)\s+)?([a-zA-Z0-9_]+)\s*=\s*([^;]+);\s*\1\s*(<=|<)\s*([^;]+);\s*.*?\)', s)
    if m_for:
        var, start, op, end = m_for.group(1), m_for.group(2).strip(), m_for.group(3), m_for.group(4).strip()
        end_expr = f"{end} + 1" if op == '<=' else end
        return f"for {var} in range({end_expr}):" if start == '0' else f"for {var} in range({start}, {end_expr}):"

    m_while = re.match(r'while\s*\((.+)\)', s)
    if m_while:
        return f"while {_expr_to_py(m_while.group(1))}:"

    m_gets = re.search(r'gets\s*\(\s*([a-zA-Z0-9_]+)\s*\)', s)
    if m_gets:
        return f'{m_gets.group(1)} = input()'
    m_scanf = re.search(r'scanf\s*\([^,]+,\s*&?([a-zA-Z0-9_]+)\s*\)', s)
    if m_scanf:
        return f'{m_scanf.group(1)} = int(input())' if '%d' in s else f'{m_scanf.group(1)} = input()'
    m_cin = re.search(r'(?:std::)?cin\s*>>\s*([a-zA-Z0-9_]+)', s)
    if m_cin:
        return f'{m_cin.group(1)} = input()'
    m_getline = re.search(r'(?:std::)?getline\s*\(\s*(?:std::)?cin\s*,\s*([a-zA-Z0-9_]+)\s*\)', s)
    if m_getline:
        return f'{m_getline.group(1)} = input()'
    if 'Scanner' in s or '.nextLine()' in s or '.nextInt()' in s or '.nextDouble()' in s or '.next()' in s:
        m_var = re.match(r'(?:(?:String|int|double|float)\s+)?([a-zA-Z0-9_]+)\s*=', s)
        if m_var:
            if '.nextInt()' in s:
                return f'{m_var.group(1)} = int(input())'
            if '.nextDouble()' in s or '.nextFloat()' in s:
                return f'{m_var.group(1)} = float(input())'
            return f'{m_var.group(1)} = input()'
        return None

    if s.startswith('printf('):
        m = re.search(r'printf\s*\(\s*\"(.*?)\"(?:\s*,\s*(.*?))?\s*\)', s)
        if m:
            fmt = m.group(1).replace(r'\n', '')
            args = m.group(2)
            if args:
                for a in [arg.strip() for arg in args.split(',')]:
                    fmt = re.sub(r'%[dsfldu]', f'{{{a}}}', fmt, count=1)
                return f'print(f"{fmt}")'
            return f'print("{fmt}")'
        m_v = re.search(r'printf\s*\(\s*([a-zA-Z0-9_]+)\s*\)', s)
        if m_v:
            return f'print({m_v.group(1)})'

    if s.startswith('System.out.println(') or s.startswith('System.out.print('):
        m = re.search(r'System\.out\.print(?:ln)?\s*\((.+)\)', s)
        if m:
            return f'print({m.group(1)})'

    if 'cout' in s:
        cleaned = re.sub(r'^(?:std::)?cout\s*<<\s*', '', s)
        cleaned = re.sub(r'\s*<<\s*(?:std::)?endl$', '', cleaned)
        parts = [p.strip() for p in cleaned.split('<<') if p.strip()]
        return f'print({", ".join(parts)})'

    m_cpy = re.search(r'strcpy\s*\(\s*([a-zA-Z0-9_]+)\s*,\s*(.+)\)', s)
    if m_cpy:
        return f"{m_cpy.group(1)} = {m_cpy.group(2)}"

    if s.startswith('return'):
        return _expr_to_py(s)

    if s.startswith('delete'):
        return None

    m_decl = re.match(
        r'^(?:(?:const\s+)?(?:int|char|float|double|bool|boolean|String|string|std::string|auto)\s*\*?\s*)'
        r'([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[\s*\d*\s*\])?\s*=\s*(.+)$',
        s
    )
    if m_decl:
        var_name = m_decl.group(1)
        val = m_decl.group(2).strip()
        if val.startswith('new '):
            return f"{var_name} = []"
        return f"{var_name} = {_expr_to_py(val)}"

    m_uninit = re.match(
        r'^(?:int|char|float|double|bool|boolean|String|string|std::string|auto)\s*\*?\s*'
        r'([a-zA-Z_][a-zA-Z0-9_]*)(?:\[\s*(\d*)\s*\])?$',
        s
    )
    if m_uninit:
        var_name = m_uninit.group(1)
        is_arr = m_uninit.group(2) is not None
        return f'{var_name} = ""' if is_arr else f"{var_name} = 0"

    return _expr_to_py(s)

def _expr_to_py(expr):
    e = expr.replace('true', 'True').replace('false', 'False').replace('null', 'None').replace('NULL', 'None')
    e = re.sub(r'\bRuntime\.getRuntime\(\)\.exec\(', 'os.system(', e)
    e = re.sub(r'(\w+)\+\+', r'\1 += 1', e)
    e = re.sub(r'(\w+)--', r'\1 -= 1', e)
    return e

def _emit_java(functions, scanner_vars=None):
    has_scanner = any(
        any(k in l for k in ['gets(', 'scanf(', 'cin', 'getline', 'Scanner'])
        for fn in functions for l in fn['raw_lines']
    )
    out = []
    if has_scanner:
        out.append("import java.util.Scanner;\n")
    out.append("public class Main {")
    if has_scanner:
        out.append("    private static Scanner scanner = new Scanner(System.in);\n")

    for fn in functions:
        ret_t = _normalize_c_type(fn['ret_type'], 'java')
        if fn['is_main']:
            out.append("    public static void main(String[] args) {")
        else:
            p_str = ", ".join(f"{_normalize_c_type(p['type'], 'java')} {p['name']}" for p in fn['params'])
            out.append(f"    public static {ret_t} {fn['name']}({p_str}) {{")

        indent = 2
        for raw in fn['raw_lines']:
            s = raw.strip()
            if not s:
                continue
            if s.startswith('}'):
                indent = max(2, indent - 1)
            pad = "    " * indent
            j_line = _stmt_to_java(s, fn['is_main'])
            if j_line:
                out.append(f"{pad}{j_line}")
            if s.endswith('{') and not s.startswith('}'):
                indent += 1
            elif '} else' in s and s.endswith('{'):
                indent += 1

        out.append("    }\n")
    out.append("}")
    return "\n".join(out)

def _stmt_to_java(s, is_main):
    if s in ['{', '}']:
        return s
    if is_main and re.match(r'^return\s+0\s*;?$', s):
        return None
    if s.startswith('delete'):
        return None

    clean = s.rstrip(';').strip()
    clean = re.sub(r'\bchar\s+([a-zA-Z0-9_]+)\s*\[\s*\d*\s*\]\s*=\s*(.+)', r'String \1 = \2', clean)
    clean = re.sub(r'\bchar\s+([a-zA-Z0-9_]+)\s*\[\s*\d*\s*\]', r'String \1 = ""', clean)
    clean = re.sub(r'\bconst\s+char\*\s*', 'String ', clean)
    clean = re.sub(r'\b(?:std::)?string\b', 'String', clean)
    clean = re.sub(r'\bbool\b', 'boolean', clean)

    m_gets = re.search(r'gets\s*\(\s*([a-zA-Z0-9_]+)\s*\)', clean)
    if m_gets:
        return f"{m_gets.group(1)} = scanner.nextLine();"
    m_scanf = re.search(r'scanf\s*\([^,]+,\s*&?([a-zA-Z0-9_]+)\s*\)', clean)
    if m_scanf:
        return f"{m_scanf.group(1)} = scanner.nextInt();" if '%d' in clean else f"{m_scanf.group(1)} = scanner.nextLine();"
    m_cin = re.search(r'(?:std::)?cin\s*>>\s*([a-zA-Z0-9_]+)', clean)
    if m_cin:
        return f"{m_cin.group(1)} = scanner.nextLine();"
    m_getline = re.search(r'(?:std::)?getline\s*\(\s*(?:std::)?cin\s*,\s*([a-zA-Z0-9_]+)\s*\)', clean)
    if m_getline:
        return f"{m_getline.group(1)} = scanner.nextLine();"

    m_cpy = re.search(r'strcpy\s*\(\s*([a-zA-Z0-9_]+)\s*,\s*(.+)\)', clean)
    if m_cpy:
        return f"{m_cpy.group(1)} = {m_cpy.group(2)};"

    if clean.startswith('printf('):
        m = re.search(r'printf\s*\(\s*\"(.*?)\"(?:\s*,\s*(.*?))?\s*\)', clean)
        if m:
            fmt = m.group(1).replace(r'\n', '')
            args = m.group(2)
            return f'System.out.printf("{fmt}%n", {args});' if args else f'System.out.println("{fmt}");'
        m_v = re.search(r'printf\s*\(\s*([a-zA-Z0-9_]+)\s*\)', clean)
        if m_v:
            return f'System.out.println({m_v.group(1)});'

    if 'cout' in clean:
        cleaned = re.sub(r'^(?:std::)?cout\s*<<\s*', '', clean)
        cleaned = re.sub(r'\s*<<\s*(?:std::)?endl$', '', cleaned)
        parts = [p.strip() for p in cleaned.split('<<') if p.strip()]
        return f'System.out.println({" + ".join(parts)});'

    if clean.endswith('{') or clean.endswith('}'):
        return clean
    return clean + ';'

def _emit_cpp(functions, scanner_vars=None):
    scanner_vars = scanner_vars or set()
    out = ['#include <iostream>', '#include <string>', '', 'using namespace std;', '']
    for fn in functions:
        # C++ requires `int main()` instead of `void main()`
        ret_t = 'int' if fn['is_main'] else _normalize_c_type(fn['ret_type'], 'cpp')
        p_str = ", ".join(f"{_normalize_c_type(p['type'], 'cpp')} {p['name']}" for p in fn['params'])
        out.append(f"{ret_t} {fn['name']}({p_str}) {{")
        indent = 1
        emitted_lines = []
        for raw in fn['raw_lines']:
            s = raw.strip()
            if not s or _is_scanner_noise(s, scanner_vars):
                continue
            if s.startswith('}'):
                indent = max(1, indent - 1)
            pad = "    " * indent
            res_lines = _stmt_to_cpp(s, pad)
            for l in res_lines:
                emitted_lines.append(l)
            if s.endswith('{') and not s.startswith('}'):
                indent += 1
            elif '} else' in s and s.endswith('{'):
                indent += 1

        if fn['is_main'] and not any('return ' in l for l in emitted_lines):
            emitted_lines.append("    return 0;")
        out.extend(emitted_lines)
        out.append("}\n")
    return "\n".join(out).strip()

def _stmt_to_cpp(s, pad="    "):
    if s in ['{', '}']:
        return [f"{pad}{s}"]
    clean = s.rstrip(';').strip()

    clean = re.sub(r'\b(?:String|std::string)\b', 'string', clean)
    clean = re.sub(r'\bconst\s+char\*\s*', 'string ', clean)
    clean = re.sub(r'\bboolean\b', 'bool', clean)
    clean = re.sub(r'\bchar\s+([a-zA-Z0-9_]+)\s*\[\s*\d*\s*\]\s*=\s*(.+)', r'string \1 = \2', clean)
    clean = re.sub(r'\bchar\s+([a-zA-Z0-9_]+)\s*\[\s*\d*\s*\]', r'string \1', clean)

    m_gets = re.search(r'gets\s*\(\s*([a-zA-Z0-9_]+)\s*\)', clean)
    if m_gets:
        return [f"{pad}getline(cin, {m_gets.group(1)});"]
    m_scanf = re.search(r'scanf\s*\([^,]+,\s*&?([a-zA-Z0-9_]+)\s*\)', clean)
    if m_scanf:
        return [f"{pad}cin >> {m_scanf.group(1)};"]

    # Java Scanner methods: input.nextInt(), input.nextDouble(), input.nextLine(), input.next()
    m_j_int = re.match(r'^(int\s+)?([a-zA-Z0-9_]+)\s*=\s*[a-zA-Z0-9_]+\.nextInt\(\)$', clean)
    if m_j_int:
        var_name = m_j_int.group(2)
        res = []
        if m_j_int.group(1):
            res.append(f"{pad}int {var_name};")
        res.append(f"{pad}cin >> {var_name};")
        return res

    m_j_dbl = re.match(r'^((?:double|float)\s+)?([a-zA-Z0-9_]+)\s*=\s*[a-zA-Z0-9_]+\.(?:nextDouble|nextFloat)\(\)$', clean)
    if m_j_dbl:
        var_name = m_j_dbl.group(2)
        res = []
        if m_j_dbl.group(1):
            res.append(f"{pad}double {var_name};")
        res.append(f"{pad}cin >> {var_name};")
        return res

    m_j_str = re.match(r'^(string\s+)?([a-zA-Z0-9_]+)\s*=\s*[a-zA-Z0-9_]+\.(?:nextLine|next)\(\)$', clean)
    if m_j_str:
        var_name = m_j_str.group(2)
        res = []
        if m_j_str.group(1):
            res.append(f"{pad}string {var_name};")
        res.append(f"{pad}getline(cin, {var_name});")
        return res

    m_cpy = re.search(r'strcpy\s*\(\s*([a-zA-Z0-9_]+)\s*,\s*(.+)\)', clean)
    if m_cpy:
        return [f"{pad}{m_cpy.group(1)} = {m_cpy.group(2)};"]

    if clean.startswith('printf('):
        m = re.search(r'printf\s*\(\s*\"(.*?)\"(?:\s*,\s*(.*?))?\s*\)', clean)
        if m:
            fmt = m.group(1).replace(r'\n', '')
            args = m.group(2)
            if args:
                arg_list = [a.strip() for a in args.split(',')]
                tokens = re.split(r'(%[dsflc])', fmt)
                cout_parts = []
                arg_idx = 0
                for tok in tokens:
                    if not tok:
                        continue
                    if re.match(r'^%[dsflc]$', tok) and arg_idx < len(arg_list):
                        cout_parts.append(arg_list[arg_idx])
                        arg_idx += 1
                    else:
                        cout_parts.append(f'"{tok}"')
                return [f"{pad}cout << {' << '.join(cout_parts)} << endl;"]
            return [f'{pad}cout << "{fmt}" << endl;']
        m_v = re.search(r'printf\s*\(\s*([a-zA-Z0-9_]+)\s*\)', clean)
        if m_v:
            return [f"{pad}cout << {m_v.group(1)} << endl;"]

    if clean.startswith('System.out.println(') or clean.startswith('System.out.print('):
        is_ln = 'println' in clean
        m = re.search(r'System\.out\.print(?:ln)?\s*\((.+)\)', clean)
        if m:
            parts = [p.strip() for p in m.group(1).split('+')]
            suffix = " << endl" if is_ln else ""
            return [f"{pad}cout << {' << '.join(parts)}{suffix};"]

    clean = clean.replace('std::cout', 'cout').replace('std::cin', 'cin').replace('std::endl', 'endl').replace('std::getline', 'getline')

    if clean.endswith('{') or clean.endswith('}'):
        return [f"{pad}{clean}"]
    return [f"{pad}{clean};"]

def _emit_c(functions, scanner_vars=None):
    scanner_vars = scanner_vars or set()
    out = ['#include <stdio.h>', '#include <stdlib.h>', '#include <string.h>', '']
    for fn in functions:
        # C standard requires `int main()` instead of `void main()`
        ret_t = 'int' if fn['is_main'] else _normalize_c_type(fn['ret_type'], 'c')
        p_str = ", ".join(f"{_normalize_c_type(p['type'], 'c')} {p['name']}" for p in fn['params'])
        out.append(f"{ret_t} {fn['name']}({p_str}) {{")
        indent = 1
        emitted_lines = []
        for raw in fn['raw_lines']:
            s = raw.strip()
            if not s or _is_scanner_noise(s, scanner_vars):
                continue
            if s.startswith('}'):
                indent = max(1, indent - 1)
            pad = "    " * indent
            res_lines = _stmt_to_c(s, pad)
            for l in res_lines:
                emitted_lines.append(l)
            if s.endswith('{') and not s.startswith('}'):
                indent += 1
            elif '} else' in s and s.endswith('{'):
                indent += 1

        if fn['is_main'] and not any('return ' in l for l in emitted_lines):
            emitted_lines.append("    return 0;")
        out.extend(emitted_lines)
        out.append("}\n")
    return "\n".join(out).strip()

def _stmt_to_c(s, pad="    "):
    if s in ['{', '}']:
        return [f"{pad}{s}"]
    clean = s.rstrip(';').strip()
    if clean.startswith('delete'):
        return []
    clean = re.sub(r'\b(?:String|string|std::string)\b', 'const char*', clean)
    clean = re.sub(r'\b(?:bool|boolean)\b', 'int', clean)
    clean = clean.replace('true', '1').replace('false', '0')

    m_gets = re.search(r'gets\s*\(\s*([a-zA-Z0-9_]+)\s*\)', clean)
    if m_gets:
        return [f"{pad}fgets({m_gets.group(1)}, sizeof({m_gets.group(1)}), stdin);"]
    m_cin = re.search(r'(?:std::)?cin\s*>>\s*([a-zA-Z0-9_]+)', clean)
    if m_cin:
        return [f'{pad}scanf("%s", {m_cin.group(1)});']
    m_getline = re.search(r'(?:std::)?getline\s*\(\s*(?:std::)?cin\s*,\s*([a-zA-Z0-9_]+)\s*\)', clean)
    if m_getline:
        return [f"{pad}fgets({m_getline.group(1)}, sizeof({m_getline.group(1)}), stdin);"]

    # Java Scanner methods: input.nextInt(), input.nextDouble(), input.nextLine(), input.next()
    m_j_int = re.match(r'^(int\s+)?([a-zA-Z0-9_]+)\s*=\s*[a-zA-Z0-9_]+\.nextInt\(\)$', clean)
    if m_j_int:
        var_name = m_j_int.group(2)
        res = []
        if m_j_int.group(1):
            res.append(f"{pad}int {var_name};")
        res.append(f'{pad}scanf("%d", &{var_name});')
        return res

    m_j_dbl = re.match(r'^((?:double|float)\s+)?([a-zA-Z0-9_]+)\s*=\s*[a-zA-Z0-9_]+\.(?:nextDouble|nextFloat)\(\)$', clean)
    if m_j_dbl:
        var_name = m_j_dbl.group(2)
        res = []
        if m_j_dbl.group(1):
            res.append(f"{pad}double {var_name};")
        res.append(f'{pad}scanf("%lf", &{var_name});')
        return res

    m_j_str = re.match(r'^(const char\*\s+)?([a-zA-Z0-9_]+)\s*=\s*[a-zA-Z0-9_]+\.(?:nextLine|next)\(\)$', clean)
    if m_j_str:
        var_name = m_j_str.group(2)
        res = []
        if m_j_str.group(1):
            res.append(f"{pad}char {var_name}[128];")
        res.append(f"{pad}fgets({var_name}, sizeof({var_name}), stdin);")
        return res

    # System.out.println(...) / System.out.print(...)
    if clean.startswith('System.out.println(') or clean.startswith('System.out.print('):
        is_ln = 'println' in clean
        m = re.search(r'System\.out\.print(?:ln)?\s*\((.+)\)', clean)
        if m:
            arg = m.group(1).strip()
            newline_suffix = "\\n" if is_ln else ""
            if arg.startswith('"') and arg.endswith('"') and '+' not in arg:
                inner_str = arg[1:-1]
                return [f'{pad}printf("{inner_str}{newline_suffix}");']
            return [f'{pad}printf("%d{newline_suffix}", {arg});']

    if 'cout' in clean:
        cleaned = re.sub(r'^(?:std::)?cout\s*<<\s*', '', clean)
        has_endl = 'endl' in cleaned
        cleaned = re.sub(r'\s*<<\s*(?:std::)?endl$', '', cleaned)
        parts = [p.strip() for p in cleaned.split('<<') if p.strip()]
        nl = "\\n" if has_endl else ""
        if len(parts) == 1 and parts[0].startswith('"'):
            inner = parts[0][1:-1]
            return [f'{pad}printf("{inner}{nl}");']
        return [f'{pad}printf("%s{nl}", {parts[0]});']

    if clean.endswith('{') or clean.endswith('}'):
        return [f"{pad}{clean}"]
    return [f"{pad}{clean};"]
