def enrich(report):
    stats = report.instruction_stats

    total = stats.get("total", 1)

    memory_ratio = (stats["loads"] + stats["stores"]) / total
    branch_ratio = stats["branches"] / total
    mul_ratio = stats["mul_div"] / total

    report.heuristics = {
        "memory_intensity": memory_ratio,
        "branch_density": branch_ratio,
        "compute_intensity": 1 - memory_ratio,
        "risk_score": round(
            0.4 * memory_ratio +
            0.3 * branch_ratio +
            0.3 * mul_ratio,
            3
        )
    }

    return report