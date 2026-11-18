#!/usr/bin/env python3
import sys
import os

from app import run_pipeline

SAMPLES = {
    "c": '''int main() {
    char password[32] = "super_secret_123";
    char user_input[100];
    int uninit_num;
    int calculated = uninit_num + 10;
    
    gets(user_input);
    printf(user_input);
    strcpy(user_input, "dangerous");
    return 0;
}''',
    "cpp": '''int main() {
    char token[32] = "admin_master_cpp_token";
    char buffer[64];
    int* leak_ptr = new int[50];
    
    gets(buffer);
    printf(buffer);
    return 0;
}''',
    "python": '''import os
import pickle

admin_token = "secret_api_token_xyz"

def run_query(user_val):
    sql = "SELECT * FROM users WHERE id = " + user_val
    os.system("echo " + user_val)
    data = pickle.loads(b"cos\\nsystem\\n(S'ls'\\ntR.")
    eval("2 + 2")
''',
    "java": '''public class VulnerabilityDemo {
    public static void main(String[] args) {
        String apiKey = "AIzaSyD-1234567890Secret";
        String userInput = args[0];
        
        Runtime.getRuntime().exec("ping " + userInput);
        String sql = "SELECT * FROM accounts WHERE id = " + userInput;
        stmt.executeQuery(sql);
    }
}'''
}

def main():
    print("=" * 64)
    print("   SECURE COMPILER: MULTI-LANGUAGE VULNERABILITY ANALYZER   ")
    print("=" * 64)
    print("\n[STEP 1] Please select the programming language to analyze:")
    print("  [1] C Language (.c)")
    print("  [2] C++ Language (.cpp)")
    print("  [3] Python (.py)")
    print("  [4] Java (.java)")
    
    choice = input("\nEnter choice [1-4] (default: 1): ").strip()
    lang_map = {"1": "c", "2": "cpp", "3": "python", "4": "java"}
    lang = lang_map.get(choice, "c")
    lang_names = {"c": "C", "cpp": "C++", "python": "Python", "java": "Java"}
    print(f"\n--> Selected Language: {lang_names[lang]}")

    print("\n[STEP 2] Choose code input method:")
    print(f"  [1] Run bundled vulnerable {lang_names[lang]} sample code")
    print("  [2] Enter file path to analyze")
    print("  [3] Paste source code interactively")

    input_choice = input("\nEnter input choice [1-3] (default: 1): ").strip()

    code = ""
    if input_choice == "2":
        filepath = input("Enter path to source file: ").strip()
        if not os.path.exists(filepath):
            print(f"Error: File '{filepath}' does not exist.")
            return
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            code = f.read()
    elif input_choice == "3":
        print("Paste your code below (type 'END' on a single line to finish):")
        lines = []
        while True:
            line = input()
            if line.strip() == "END":
                break
            lines.append(line)
        code = "\n".join(lines)
    else:
        code = SAMPLES[lang]

    print(f"\nCompiling and analyzing {lang_names[lang]} source code...")
    result = run_pipeline(code, language=lang)

    if not result.get("success"):
        print(f"\n[!] {result.get('stage', 'Error')}:")
        for err in result.get("errors", []):
            print(f"    - {err}")
        return

    rp = result["risk_profile"]
    print("\n" + "=" * 64)
    print("             OVERALL PROGRAM RISK EVALUATION")
    print("=" * 64)
    print(f"Risk Threat Score: {rp['score']} / 100")
    print(f"Threat Tier:       {rp['level']}")
    print(f"Summary:           {rp['summary']}")
    print(f"Total Findings:    {len(result['findings'])} (High: {rp['counts']['HIGH']}, Med: {rp['counts']['MEDIUM']})")

    print("\n" + "=" * 64)
    print("       IDENTIFIED WEAK PARTS & VULNERABLE LEXEMES")
    print("=" * 64)

    if not result["findings"]:
        print("No vulnerabilities detected! The code parsed cleanly without security warnings.")
    else:
        for idx, f in enumerate(result["findings"], 1):
            print(f"\n#{idx} [{f['rule_id']}] {f['title']} ({f['severity']})")
            print(f"    Line Number:     Line {f['line']}")
            print(f"    Weak Lexeme:     {f.get('lexeme', 'N/A')}")
            print(f"    Source Context:  {f['evidence']}")
            print(f"    Description:     {f['description']}")
            print(f"    Mitigation:      {f['recommendation']}")

    print("\n" + "=" * 64)
    print("Analysis complete.")

if __name__ == "__main__":
    main()
