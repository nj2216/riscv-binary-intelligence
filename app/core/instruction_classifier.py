LOADS = {"lb","lh","lw","ld","lbu","lhu","lwu"}
STORES = {"sb","sh","sw","sd"}
BRANCHES = {"beq","bne","blt","bge","jal","jalr"}
MULDIV = {"mul","mulh","div","rem"}

def enrich(report):
    stats = {
        "total": 0,
        "loads": 0,
        "stores": 0,
        "branches": 0,
        "arithmetic": 0,
        "mul_div": 0,
        "floating": 0,
        "compressed": 0
    }

    for ins in report.instructions:
        if ins["size"] == 2:
            stats["compressed"] += 1
        m = ins["mnemonic"]
        stats["total"] += 1

        if m in LOADS:
            stats["loads"] += 1
        elif m in STORES:
            stats["stores"] += 1
        elif m in BRANCHES:
            stats["branches"] += 1
        elif m in MULDIV:
            stats["mul_div"] += 1
        elif m.startswith("f"):
            stats["floating"] += 1
        else:
            stats["arithmetic"] += 1
        
    report.instruction_stats = stats
    return report