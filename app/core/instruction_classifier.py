LOADS = {"lb","lh","lw","ld","lbu","lhu","lwu","c.ld","c.ldsp","c.lw","c.lwsp"}
STORES = {"sb","sh","sw","sd","c.sd","c.sdsp","c.sw","c.swsp"}
BRANCHES = {"beq","bne","blt","bge","jal","jalr","c.jal","c.jalr","c.j","c.jr","c.beqz","c.bnez"}
MULDIV = {"mul","mulh","div","rem","c.mul","c.div"}
COMPRESSED = {"c.addi","c.addiw","c.addw","c.add","c.mv","c.li","c.lui","c.sub","c.subw","c.and","c.andi","c.or","c.xor","c.slli","c.srli","c.srai"}

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
        elif m in COMPRESSED:
            stats["arithmetic"] += 1
        else:
            stats["arithmetic"] += 1
        
    report.instruction_stats = stats
    return report