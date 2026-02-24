def enrich(report):
    stats = {
        "total": 0,
        "loads": 0,
        "stores": 0,
        "branches": 0,
        "arithmetic": 0,
        "mul_div": 0,
        "floating": 0
    }

    for ins in report.instructions:
        m = ins["mnemonic"]
        stats["total"] += 1

        if m.startswith("l"):
            stats["loads"] += 1
        elif m.startswith("s"):
            stats["stores"] += 1
        elif m in ["beq", "bne", "jal", "jalr"]:
            stats["branches"] += 1
        elif m in ["mul", "div", "rem"]:
            stats["mul_div"] += 1
        elif m.startswith("f"):
            stats["floating"] += 1
        else:
            stats["arithmetic"] += 1
        
        report.instruction_stats = stats
        return report