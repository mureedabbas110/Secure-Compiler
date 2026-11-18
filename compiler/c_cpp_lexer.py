import ply.lex as lex

tokens = (
    'IDENTIFIER', 'INT_CONST', 'FLOAT_CONST', 'STRING_LITERAL', 'CHAR_LITERAL',
    'INT', 'CHAR', 'VOID', 'FLOAT', 'DOUBLE', 'BOOL', 'STRING_TYPE',
    'LONG', 'SHORT', 'UNSIGNED', 'CONST',
    'USING', 'NAMESPACE', 'STD',
    'CLASS', 'STRUCT', 'PUBLIC', 'PRIVATE', 'PROTECTED',
    'NEW', 'DELETE',
    'IF', 'ELSE', 'WHILE', 'FOR', 'DO', 'BREAK', 'CONTINUE', 'RETURN',
    'CIN', 'COUT', 'ENDL', 'GETLINE',
    'TRUE', 'FALSE', 'NULLPTR',
    'PLUSPLUS', 'MINUSMINUS',
    'PLUSEQ', 'MINUSEQ', 'TIMESEQ', 'DIVEQ', 'MODEQ',
    'SHL', 'SHR', 'SCOPE', 'ARROW',
    'AND', 'OR', 'NOT',
    'BITAND', 'BITNOT',
    'PLUS', 'MINUS', 'TIMES', 'DIVIDE', 'MODULO',
    'ASSIGN', 'EQ', 'NEQ', 'LT', 'LE', 'GT', 'GE',
    'LPAREN', 'RPAREN', 'LBRACE', 'RBRACE', 'LBRACKET', 'RBRACKET',
    'SEMICOLON', 'COMMA', 'COLON', 'DOT'
)

reserved = {
    'int': 'INT',
    'char': 'CHAR',
    'void': 'VOID',
    'float': 'FLOAT',
    'double': 'DOUBLE',
    'bool': 'BOOL',
    'string': 'STRING_TYPE',
    'long': 'LONG',
    'short': 'SHORT',
    'unsigned': 'UNSIGNED',
    'const': 'CONST',
    'using': 'USING',
    'namespace': 'NAMESPACE',
    'std': 'STD',
    'class': 'CLASS',
    'struct': 'STRUCT',
    'public': 'PUBLIC',
    'private': 'PRIVATE',
    'protected': 'PROTECTED',
    'new': 'NEW',
    'delete': 'DELETE',
    'if': 'IF',
    'else': 'ELSE',
    'while': 'WHILE',
    'for': 'FOR',
    'do': 'DO',
    'break': 'BREAK',
    'continue': 'CONTINUE',
    'return': 'RETURN',
    'cin': 'CIN',
    'cout': 'COUT',
    'endl': 'ENDL',
    'getline': 'GETLINE',
    'true': 'TRUE',
    'false': 'FALSE',
    'nullptr': 'NULLPTR',
    'NULL': 'NULLPTR'
}

t_SCOPE      = r'::'
t_ARROW      = r'->'
t_SHL        = r'<<'
t_SHR        = r'>>'
t_PLUSPLUS   = r'\+\+'
t_MINUSMINUS = r'--'
t_PLUSEQ     = r'\+='
t_MINUSEQ    = r'-='
t_TIMESEQ    = r'\*='
t_DIVEQ      = r'/='
t_MODEQ      = r'%='
t_AND        = r'&&'
t_OR         = r'\|\|'
t_NOT        = r'!'
t_BITAND     = r'&'
t_BITNOT     = r'~'
t_PLUS       = r'\+'
t_MINUS      = r'-'
t_TIMES      = r'\*'
t_DIVIDE     = r'/'
t_MODULO     = r'%'
t_ASSIGN     = r'='
t_EQ         = r'=='
t_NEQ        = r'!='
t_LE         = r'<='
t_GE         = r'>='
t_LT         = r'<'
t_GT         = r'>'
t_LPAREN     = r'\('
t_RPAREN     = r'\)'
t_LBRACE     = r'\{'
t_RBRACE     = r'\}'
t_LBRACKET   = r'\['
t_RBRACKET   = r'\]'
t_SEMICOLON  = r';'
t_COMMA      = r','
t_COLON      = r':'
t_DOT        = r'\.'

t_ignore = ' \t\r'

def t_PREPROCESSOR(t):
    r'\#[^\n]*'
    pass

def t_COMMENT_MULTI(t):
    r'/\*(.|\n)*?\*/'
    t.lexer.lineno += t.value.count('\n')

def t_COMMENT_SINGLE(t):
    r'//[^\n]*'
    pass

def t_STRING_LITERAL(t):
    r'\"([^\\\n]|(\\.))*?\"'
    return t

def t_CHAR_LITERAL(t):
    r"\'([^\\\n]|(\\.))\'"
    return t

def t_FLOAT_CONST(t):
    r'\d+\.\d+([eE][+-]?\d+)?[fFlL]?'
    t.value = float(t.value.rstrip('fFlL'))
    return t

def t_INT_CONST(t):
    r'\d+[uUlL]*'
    t.value = int(t.value.rstrip('uUlL'))
    return t

def t_IDENTIFIER(t):
    r'[a-zA-Z_][a-zA-Z0-9_]*'
    t.type = reserved.get(t.value, 'IDENTIFIER')
    return t

def t_newline(t):
    r'\n+'
    t.lexer.lineno += len(t.value)

def t_error(t):
    t.lexer.errors.append(f"Illegal character '{t.value[0]}' at line {t.lexer.lineno}")
    t.lexer.skip(1)

def build_c_lexer():
    l = lex.lex()
    l.errors = []
    return l
