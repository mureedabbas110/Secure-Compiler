# Multi-Language Secure Compiler & Static Vulnerability Analyzer
Supporting **C, C++, Python, and Java** with upfront language selection, compiler phase inspection, exact lexeme extraction, line tracking, threat scoring, and PDF report export.

## Key Capabilities
- **Upfront Language Selection**: The application explicitly prompts the user to select the target language (C, C++, Python, or Java) before accepting and compiling the source code.
- **Accurate Weak Part & Lexeme Identification**: Pinpoints the exact line number, vulnerable code lexeme (e.g., `gets()`, `eval()`, `Runtime.getRuntime().exec()`), raw evidence, and recommended mitigation.
- **Compiler Front-End Pipelines**:
  - **C & C++**: Custom PLY (Lex/Yacc) lexer and parser generating tokens, symbol table, and AST.
  - **Python**: Native Python `ast` and `tokenize` engine analyzing bytecode and syntax trees.
  - **Java**: Java AST tokenizer and semantic pattern recognizer.
- **Overall Program Risk Strength Meter**: 0 to 100 aggregated threat scoring with visual risk gauge (Clean, Low, Moderate, High, Critical).
- **Dual Interface Modes**:
  1. **Web Dashboard**: Interactive two-step wizard with visual language cards, sample loaders, compiler tabs, and ReportLab PDF export.
  2. **Interactive CLI (`cli_analyzer.py`)**: Terminal workflow that interactively asks for language, input mode, and prints exact weak parts.
- **Authentication**: SQLite-backed user registration and login session management.

## Quick Start

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run automated tests:
   ```bash
   python -m pytest tests/test_compiler.py
   ```

3. Launch Web Application:
   ```bash
   python app.py
   ```
   Open `http://127.0.0.1:5000` in your web browser.

4. Or Run Terminal Interactive Analyzer:
   ```bash
   python cli_analyzer.py
   ```
