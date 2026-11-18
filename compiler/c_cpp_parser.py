import ply.yacc as yacc
from compiler.c_cpp_lexer import tokens
from compiler.ast_nodes import ASTNode

precedence = (
    ('right', 'ASSIGN', 'PLUSEQ', 'MINUSEQ', 'TIMESEQ', 'DIVEQ', 'MODEQ'),
    ('left', 'OR'),
    ('left', 'AND'),
    ('left', 'BITAND'),
    ('left', 'EQ', 'NEQ'),
    ('left', 'LT', 'LE', 'GT', 'GE'),
    ('left', 'SHL', 'SHR'),
    ('left', 'PLUS', 'MINUS'),
    ('left', 'TIMES', 'DIVIDE', 'MODULO'),
    ('right', 'NOT', 'BITNOT', 'UMINUS', 'ADDR', 'DEREF'),
    ('left', 'PLUSPLUS', 'MINUSMINUS', 'DOT', 'ARROW', 'LBRACKET', 'LPAREN'),
)

def p_program(p):
    '''program : declaration_list
               | empty'''
    p[0] = ASTNode('Program', line=1, declarations=p[1] if p[1] else [])

def p_declaration_list(p):
    '''declaration_list : declaration_list declaration
                        | declaration'''
    if len(p) == 3:
        p[0] = p[1] + [p[2]]
    else:
        p[0] = [p[1]]

def p_declaration(p):
    '''declaration : using_directive
                   | var_declaration
                   | func_declaration
                   | func_prototype
                   | class_declaration
                   | SEMICOLON'''
    if p[1] == ';':
        p[0] = ASTNode('EmptyDecl', line=p.lineno(1))
    else:
        p[0] = p[1]

def p_using_directive(p):
    '''using_directive : USING NAMESPACE STD SEMICOLON
                       | USING NAMESPACE IDENTIFIER SEMICOLON
                       | USING STD SCOPE IDENTIFIER SEMICOLON'''
    p[0] = ASTNode('UsingDirective', line=p.lineno(1), target=p[3] if len(p) == 5 else p[4])

def p_type(p):
    '''type : base_type
            | base_type TIMES
            | base_type BITAND
            | CONST base_type
            | CONST base_type TIMES
            | CONST base_type BITAND
            | STD SCOPE STRING_TYPE
            | CONST STD SCOPE STRING_TYPE BITAND'''
    if len(p) == 2:
        p[0] = p[1]
    elif len(p) == 3:
        p[0] = f"{p[1]}{p[2]}" if p[2] in ['*', '&'] else f"{p[1]} {p[2]}"
    elif len(p) == 4:
        p[0] = 'std::string' if p[1] == 'std' else f"{p[1]} {p[2]}{p[3]}"
    else:
        p[0] = 'const std::string&'

def p_base_type(p):
    '''base_type : INT
                 | CHAR
                 | VOID
                 | FLOAT
                 | DOUBLE
                 | BOOL
                 | STRING_TYPE
                 | LONG
                 | SHORT
                 | UNSIGNED INT
                 | LONG LONG'''
    p[0] = p[1] if len(p) == 2 else f"{p[1]} {p[2]}"

def p_var_declaration(p):
    '''var_declaration : type init_declarator_list SEMICOLON'''
    decls = []
    for item in p[2]:
        decls.append(ASTNode(
            'VarDecl',
            line=item['line'],
            data_type=f"{p[1]}[]" if item['is_array'] else p[1],
            name=item['name'],
            size=item['size'],
            init=item['init']
        ))
    p[0] = decls[0] if len(decls) == 1 else ASTNode('MultiVarDecl', line=decls[0].line, decls=decls)

def p_init_declarator_list(p):
    '''init_declarator_list : init_declarator_list COMMA init_declarator
                            | init_declarator'''
    p[0] = p[1] + [p[3]] if len(p) == 4 else [p[1]]

def p_init_declarator(p):
    '''init_declarator : IDENTIFIER
                       | TIMES IDENTIFIER
                       | IDENTIFIER ASSIGN expression
                       | TIMES IDENTIFIER ASSIGN expression
                       | IDENTIFIER LBRACKET INT_CONST RBRACKET
                       | IDENTIFIER LBRACKET RBRACKET
                       | IDENTIFIER LBRACKET INT_CONST RBRACKET ASSIGN expression
                       | IDENTIFIER LBRACKET RBRACKET ASSIGN expression'''
    if p[1] == '*':
        line = p.lineno(2)
        p[0] = {'name': p[2], 'line': line, 'is_array': False, 'size': None, 'init': p[4] if len(p) > 3 else None}
    else:
        line = p.lineno(1)
        if len(p) == 2:
            p[0] = {'name': p[1], 'line': line, 'is_array': False, 'size': None, 'init': None}
        elif len(p) == 4 and p[2] == '=':
            p[0] = {'name': p[1], 'line': line, 'is_array': False, 'size': None, 'init': p[3]}
        elif len(p) == 4 and p[2] == '[':
            p[0] = {'name': p[1], 'line': line, 'is_array': True, 'size': None, 'init': None}
        elif len(p) == 5:
            p[0] = {'name': p[1], 'line': line, 'is_array': True, 'size': p[3], 'init': None}
        elif len(p) == 6:
            p[0] = {'name': p[1], 'line': line, 'is_array': True, 'size': None, 'init': p[5]}
        else:
            p[0] = {'name': p[1], 'line': line, 'is_array': True, 'size': p[3], 'init': p[6]}

def p_func_prototype(p):
    '''func_prototype : type IDENTIFIER LPAREN param_list RPAREN SEMICOLON'''
    p[0] = ASTNode('FuncProto', line=p.lineno(2), return_type=p[1], name=p[2], params=p[4])

def p_func_declaration(p):
    '''func_declaration : type IDENTIFIER LPAREN param_list RPAREN compound_stmt'''
    p[0] = ASTNode('FuncDecl', line=p.lineno(2), return_type=p[1], name=p[2], params=p[4], body=p[6])

def p_class_declaration(p):
    '''class_declaration : CLASS IDENTIFIER LBRACE class_members RBRACE SEMICOLON
                         | STRUCT IDENTIFIER LBRACE class_members RBRACE SEMICOLON'''
    p[0] = ASTNode('ClassDecl', line=p.lineno(2), name=p[2], members=p[4])

def p_class_members(p):
    '''class_members : class_members class_member
                     | empty'''
    p[0] = p[1] + [p[2]] if len(p) == 3 else []

def p_class_member(p):
    '''class_member : PUBLIC COLON
                    | PRIVATE COLON
                    | PROTECTED COLON
                    | var_declaration
                    | func_declaration'''
    p[0] = ASTNode('AccessSpec', line=p.lineno(1), access=p[1]) if len(p) == 3 else p[1]

def p_param_list(p):
    '''param_list : param_list COMMA param
                  | param
                  | VOID
                  | empty'''
    if len(p) == 4:
        p[0] = p[1] + [p[3]]
    elif len(p) == 2 and p[1] not in (None, 'void'):
        p[0] = [p[1]]
    else:
        p[0] = []

def p_param(p):
    '''param : type IDENTIFIER
             | type IDENTIFIER LBRACKET RBRACKET'''
    dt = f"{p[1]}[]" if len(p) == 5 else p[1]
    p[0] = ASTNode('Param', line=p.lineno(2), data_type=dt, name=p[2])

def p_compound_stmt(p):
    '''compound_stmt : LBRACE stmt_list RBRACE'''
    p[0] = ASTNode('CompoundStmt', line=p.lineno(1), statements=p[2])

def p_stmt_list(p):
    '''stmt_list : stmt_list statement
                 | empty'''
    p[0] = p[1] + [p[2]] if len(p) == 3 else []

def p_statement(p):
    '''statement : var_declaration
                 | expr_stmt
                 | if_stmt
                 | while_stmt
                 | do_while_stmt
                 | for_stmt
                 | return_stmt
                 | break_stmt
                 | continue_stmt
                 | delete_stmt
                 | cout_stmt
                 | cin_stmt
                 | getline_stmt
                 | compound_stmt'''
    p[0] = p[1]

def p_cout_stmt(p):
    '''cout_stmt : COUT cout_chain SEMICOLON
                 | STD SCOPE COUT cout_chain SEMICOLON'''
    p[0] = ASTNode('CoutStmt', line=p.lineno(1), items=p[2] if len(p) == 4 else p[4])

def p_cout_chain(p):
    '''cout_chain : cout_chain SHL cout_item
                  | SHL cout_item'''
    p[0] = p[1] + [p[3]] if len(p) == 4 else [p[2]]

def p_cout_item(p):
    '''cout_item : ENDL
                 | STD SCOPE ENDL
                 | expression'''
    if (len(p) == 2 and p[1] == 'endl') or len(p) == 4:
        p[0] = ASTNode('Endl', line=p.lineno(1))
    else:
        p[0] = p[1]

def p_cin_stmt(p):
    '''cin_stmt : CIN cin_chain SEMICOLON
                | STD SCOPE CIN cin_chain SEMICOLON'''
    p[0] = ASTNode('CinStmt', line=p.lineno(1), targets=p[2] if len(p) == 4 else p[4])

def p_cin_chain(p):
    '''cin_chain : cin_chain SHR IDENTIFIER
                 | SHR IDENTIFIER'''
    p[0] = p[1] + [p[3]] if len(p) == 4 else [p[2]]

def p_getline_stmt(p):
    '''getline_stmt : GETLINE LPAREN CIN COMMA IDENTIFIER RPAREN SEMICOLON
                    | GETLINE LPAREN STD SCOPE CIN COMMA IDENTIFIER RPAREN SEMICOLON
                    | STD SCOPE GETLINE LPAREN STD SCOPE CIN COMMA IDENTIFIER RPAREN SEMICOLON'''
    p[0] = ASTNode('GetlineStmt', line=p.lineno(1), target=p[len(p) - 3])

def p_delete_stmt(p):
    '''delete_stmt : DELETE IDENTIFIER SEMICOLON
                   | DELETE LBRACKET RBRACKET IDENTIFIER SEMICOLON'''
    p[0] = ASTNode('DeleteStmt', line=p.lineno(1), target=p[2] if len(p) == 4 else p[4])

def p_expr_stmt(p):
    '''expr_stmt : expression SEMICOLON
                 | SEMICOLON'''
    p[0] = p[1] if len(p) == 3 else ASTNode('EmptyStmt', line=p.lineno(1))

def p_if_stmt(p):
    '''if_stmt : IF LPAREN expression RPAREN statement
               | IF LPAREN expression RPAREN statement ELSE statement'''
    line = p.lineno(1)
    p[0] = ASTNode('IfStmt', line=line, condition=p[3], then_branch=p[5], else_branch=p[7] if len(p) == 8 else None)

def p_while_stmt(p):
    '''while_stmt : WHILE LPAREN expression RPAREN statement'''
    p[0] = ASTNode('WhileStmt', line=p.lineno(1), condition=p[3], body=p[5])

def p_do_while_stmt(p):
    '''do_while_stmt : DO statement WHILE LPAREN expression RPAREN SEMICOLON'''
    p[0] = ASTNode('DoWhileStmt', line=p.lineno(1), body=p[2], condition=p[5])

def p_for_stmt(p):
    '''for_stmt : FOR LPAREN for_init for_cond SEMICOLON for_iter RPAREN statement'''
    p[0] = ASTNode('ForStmt', line=p.lineno(1), init=p[3], condition=p[4], iter=p[6], body=p[8])

def p_for_init(p):
    '''for_init : var_declaration
                | expression SEMICOLON
                | SEMICOLON'''
    p[0] = p[1] if p[1] != ';' else None

def p_for_cond(p):
    '''for_cond : expression
                | empty'''
    p[0] = p[1]

def p_for_iter(p):
    '''for_iter : expression
                | empty'''
    p[0] = p[1]

def p_return_stmt(p):
    '''return_stmt : RETURN expression SEMICOLON
                   | RETURN SEMICOLON'''
    p[0] = ASTNode('ReturnStmt', line=p.lineno(1), value=p[2] if len(p) == 4 else None)

def p_break_stmt(p):
    '''break_stmt : BREAK SEMICOLON'''
    p[0] = ASTNode('BreakStmt', line=p.lineno(1))

def p_continue_stmt(p):
    '''continue_stmt : CONTINUE SEMICOLON'''
    p[0] = ASTNode('ContinueStmt', line=p.lineno(1))

def p_expression(p):
    '''expression : assignment_expr
                  | compound_assign_expr
                  | binary_expr
                  | unary_expr
                  | postfix_expr
                  | array_access
                  | member_call
                  | member_access
                  | primary_expr
                  | func_call
                  | new_expr'''
    p[0] = p[1]

def p_new_expr(p):
    '''new_expr : NEW type
                | NEW type LBRACKET expression RBRACKET'''
    p[0] = ASTNode('NewExpr', line=p.lineno(1), allocated_type=p[2] if len(p) == 3 else f"{p[2]}[]")

def p_assignment_expr(p):
    '''assignment_expr : IDENTIFIER ASSIGN expression
                       | array_access ASSIGN expression
                       | TIMES IDENTIFIER ASSIGN expression'''
    if len(p) == 4:
        target = p[1] if isinstance(p[1], str) else p[1].name
        p[0] = ASTNode('AssignExpr', line=p.lineno(2), target=target, value=p[3])
    else:
        p[0] = ASTNode('AssignExpr', line=p.lineno(3), target=p[2], value=p[4])

def p_compound_assign_expr(p):
    '''compound_assign_expr : IDENTIFIER PLUSEQ expression
                            | IDENTIFIER MINUSEQ expression
                            | IDENTIFIER TIMESEQ expression
                            | IDENTIFIER DIVEQ expression
                            | IDENTIFIER MODEQ expression'''
    p[0] = ASTNode('AssignExpr', line=p.lineno(1), target=p[1], value=ASTNode('BinaryExpr', line=p.lineno(1), op=p[2][0], left=ASTNode('Identifier', line=p.lineno(1), name=p[1]), right=p[3]))

def p_unary_expr(p):
    '''unary_expr : MINUS expression %prec UMINUS
                  | NOT expression
                  | BITNOT expression
                  | BITAND IDENTIFIER %prec ADDR
                  | TIMES IDENTIFIER %prec DEREF
                  | PLUSPLUS IDENTIFIER
                  | MINUSMINUS IDENTIFIER'''
    if p[1] in ('&', '*'):
        p[0] = ASTNode('Identifier', line=p.lineno(2), name=p[2])
    elif p[1] in ('++', '--'):
        p[0] = ASTNode('AssignExpr', line=p.lineno(2), target=p[2], value=ASTNode('Identifier', line=p.lineno(2), name=p[2]))
    else:
        p[0] = ASTNode('UnaryExpr', line=p.lineno(1), op=p[1], operand=p[2])

def p_postfix_expr(p):
    '''postfix_expr : IDENTIFIER PLUSPLUS
                    | IDENTIFIER MINUSMINUS'''
    p[0] = ASTNode('AssignExpr', line=p.lineno(1), target=p[1], value=ASTNode('Identifier', line=p.lineno(1), name=p[1]))

def p_array_access(p):
    '''array_access : IDENTIFIER LBRACKET expression RBRACKET'''
    p[0] = ASTNode('ArrayAccess', line=p.lineno(1), name=p[1], index=p[3])

def p_member_call(p):
    '''member_call : IDENTIFIER DOT IDENTIFIER LPAREN arg_list RPAREN
                   | IDENTIFIER ARROW IDENTIFIER LPAREN arg_list RPAREN'''
    p[0] = ASTNode('MethodCall', line=p.lineno(1), object=p[1], method=p[3], args=p[5])

def p_member_access(p):
    '''member_access : IDENTIFIER DOT IDENTIFIER
                     | IDENTIFIER ARROW IDENTIFIER'''
    p[0] = ASTNode('MemberAccess', line=p.lineno(1), object=p[1], member=p[3])

def p_binary_expr(p):
    '''binary_expr : expression PLUS expression
                   | expression MINUS expression
                   | expression TIMES expression
                   | expression DIVIDE expression
                   | expression MODULO expression
                   | expression EQ expression
                   | expression NEQ expression
                   | expression LT expression
                   | expression LE expression
                   | expression GT expression
                   | expression GE expression
                   | expression AND expression
                   | expression OR expression'''
    p[0] = ASTNode('BinaryExpr', line=p.lineno(2), op=p[2], left=p[1], right=p[3])

def p_func_call(p):
    '''func_call : IDENTIFIER LPAREN arg_list RPAREN'''
    p[0] = ASTNode('FuncCall', line=p.lineno(1), name=p[1], args=p[3])

def p_arg_list(p):
    '''arg_list : arg_list COMMA expression
                | expression
                | empty'''
    if len(p) == 4:
        p[0] = p[1] + [p[3]]
    elif len(p) == 2 and p[1] is not None:
        p[0] = [p[1]]
    else:
        p[0] = []

def p_primary_expr(p):
    '''primary_expr : IDENTIFIER
                    | INT_CONST
                    | FLOAT_CONST
                    | STRING_LITERAL
                    | CHAR_LITERAL
                    | TRUE
                    | FALSE
                    | NULLPTR
                    | LPAREN expression RPAREN'''
    if len(p) == 2:
        val = p[1]
        if isinstance(val, int):
            p[0] = ASTNode('IntLiteral', line=p.lineno(1), value=val)
        elif isinstance(val, float):
            p[0] = ASTNode('FloatLiteral', line=p.lineno(1), value=val)
        elif isinstance(val, str) and val.startswith('"'):
            p[0] = ASTNode('StringLiteral', line=p.lineno(1), value=val[1:-1])
        elif isinstance(val, str) and val.startswith("'"):
            p[0] = ASTNode('CharLiteral', line=p.lineno(1), value=val[1:-1])
        elif val in ('true', 'false', 'nullptr', 'NULL'):
            p[0] = ASTNode('Literal', line=p.lineno(1), value=val)
        else:
            p[0] = ASTNode('Identifier', line=p.lineno(1), name=val)
    else:
        p[0] = p[2]

def p_empty(p):
    '''empty :'''
    pass

def p_error(p):
    if p:
        msg = f"Syntax error at '{p.value}', line {p.lineno}"
    else:
        msg = "Syntax error at end of file"
    c_parser.errors.append(msg)

c_parser = yacc.yacc(write_tables=False, debug=False)
