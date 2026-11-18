def calculate_risk_profile(findings):
    weights = {"HIGH": 30, "MEDIUM": 15, "LOW": 5}
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total_score = 0

    for f in findings:
        sev = f.get("severity", "MEDIUM").upper()
        if sev in weights:
            counts[sev] += 1
            total_score += weights[sev]
        else:
            counts["MEDIUM"] += 1
            total_score += 15

    score = min(100, total_score)

    if score == 0:
        level = "CLEAN / NO RISK"
        badge_class = "bg-emerald-100 text-emerald-800 border-emerald-300"
        bar_color = "bg-emerald-500"
        pdf_color = "#10B981"
        summary = "No vulnerable patterns or risky lexemes were identified in the analyzed code."
    elif score <= 25:
        level = "LOW RISK"
        badge_class = "bg-blue-100 text-blue-800 border-blue-300"
        bar_color = "bg-blue-500"
        pdf_color = "#3B82F6"
        summary = "Minor security warnings detected. The program structure is largely safe with low exploitability."
    elif score <= 60:
        level = "MODERATE RISK"
        badge_class = "bg-amber-100 text-amber-800 border-amber-300"
        bar_color = "bg-amber-500"
        pdf_color = "#F59E0B"
        summary = "Moderate risk exposure detected. Several insecure function calls or practices require review."
    elif score <= 85:
        level = "HIGH RISK"
        badge_class = "bg-orange-100 text-orange-800 border-orange-300"
        bar_color = "bg-orange-500"
        pdf_color = "#F97316"
        summary = "High risk security vulnerabilities detected. Exploitable patterns (such as injection or memory corruption) are present."
    else:
        level = "CRITICAL RISK"
        badge_class = "bg-rose-100 text-rose-800 border-rose-300"
        bar_color = "bg-rose-600"
        pdf_color = "#E11D48"
        summary = "Severe vulnerability saturation. Multiple critical flaws allow arbitrary execution, credential leakage, or memory corruption."

    return {
        "score": score,
        "level": level,
        "badge_class": badge_class,
        "bar_color": bar_color,
        "pdf_color": pdf_color,
        "summary": summary,
        "counts": counts,
        "total_findings": len(findings)
    }
