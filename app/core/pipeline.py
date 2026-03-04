from app.models.report import BinaryReport
from app.core import (
    elf_parser,
    disassembler,
    instruction_classifier,
    isa_detector,
    heuristics
)


def analyze(file_bytes: bytes):
    report = BinaryReport()

    report = elf_parser.enrich(report, file_bytes)
    report = disassembler.enrich(report, file_bytes)
    print("INSTRUCTION COUNT AFTER DISASM:", len(report.instructions))
    report = instruction_classifier.enrich(report)
    print("INSTRUCTION COUNT AFTER CLASSIFIER:", len(report.instructions))
    report = isa_detector.enrich(report)
    print("INSTRUCTION COUNT AFTER ISA DETECTOR:", len(report.instructions))
    report = heuristics.enrich(report)
    print("INSTRUCTION COUNT AFTER HEURISTICS:", len(report.instructions))

    # Build a more comprehensive human-readable instruction summary for UI/exports
    stats = report.instruction_stats or {}
    heur = report.heuristics or {}
    total = int(stats.get("total", 0) or 0)

    mi = float(heur.get("memory_intensity", 0) or 0)
    br = float(heur.get("branch_density", 0) or 0)
    ci = float(heur.get("compute_intensity", 0) or 0)
    rs = float(heur.get("risk_score", 0) or 0)

    # Top instruction categories (if present)
    loads = int(stats.get("loads", 0) or 0)
    stores = int(stats.get("stores", 0) or 0)
    branches = int(stats.get("branches", 0) or 0)
    arithmetic = int(stats.get("arithmetic", 0) or 0)
    mul_div = int(stats.get("mul_div", 0) or 0)

    # Largest section (if available)
    top_section = None
    try:
        secs = sorted(report.sections or [], key=lambda s: s.get("size", 0), reverse=True)
        if secs:
            ts = secs[0]
            top_section = f"{ts.get('name','(unnamed)')} (size={ts.get('size',0)})"
    except Exception:
        top_section = None

    instr_pct = lambda x: (round((x / total * 100), 1) if total else 0.0)

    summary = []
    summary.append(f"Total instructions: {total}")
    if top_section:
        summary.append(f"Largest section: {top_section}")
    summary.append(f"Memory intensity: {mi:.3f} (loads+stores {loads+stores} = {instr_pct(loads+stores)}%)")
    summary.append(f"Branch density: {br:.3f} (branches {branches} = {instr_pct(branches)}%)")
    summary.append(f"Compute intensity: {ci:.3f} (arithmetic {arithmetic}, mul/div {mul_div})")
    summary.append(f"Risk score: {rs:.3f}")

    # Add short top-3 instruction-type hints
    types = [
        ("loads", loads),
        ("stores", stores),
        ("branches", branches),
        ("arithmetic", arithmetic),
        ("mul_div", mul_div),
    ]
    types_sorted = sorted(types, key=lambda t: t[1], reverse=True)
    top_types = [f"{name} ({count})" for name, count in types_sorted if count > 0][:3]
    if top_types:
        summary.append("Top instruction types: " + ", ".join(top_types))

    report.instruction_summary = summary

    # Generate actionable recommendations (kept short and specific)
    recs = []
    # Memory-related recommendations
    if mi > 0.6:
        recs.append("High memory intensity: review data layout and reduce loads/stores.")
    elif mi > 0.4:
        recs.append("Moderate memory intensity: profile memory access patterns.")
    else:
        recs.append("Low memory intensity: compute-bound; consider algorithmic or hardware optimizations.")

    # Branching recommendations
    if br > 0.4:
        recs.append("High branch density: add branch-coverage tests and consider branch-mitigation strategies.")
    elif br > 0.2:
        recs.append("Moderate branch density: prioritize branch-heavy code paths for testing.")

    # Risk-based recommendations
    if rs > 0.6:
        recs.append("Risk score > 0.6: schedule security audit and targeted fuzzing of control-flow handlers.")
    elif rs > 0.4:
        recs.append("Elevated risk: add targeted tests and review control-flow and boundary handling.")

    # Keep list concise (cap at 6)
    report.recommendations = recs[:6]

    # Helper function for parsing operands
    def split_operands(opstr):
        """Split operand string by comma and strip whitespace"""
        return [p.strip() for p in opstr.split(',')] if opstr else []

    # Generate a simple, human-readable pseudocode listing from disassembled instructions.
    # This is a heuristic, high-level mapping to help users understand program intent.
    pseudo = []
    meta = report.metadata or {}
    if meta.get("entry_point"):
        pseudo.append(f"Entry point: {meta.get('entry_point')}")

    # mapping sets
    loads_set = {"lw","ld","lb","lh","lbu","lhu","flw","fld"}
    stores_set = {"sw","sd","sb","sh","fsw","fsd"}
    branch_set = {"beq","bne","blt","bge","bltu","bgeu"}
    jump_set = {"jal","jalr"}
    arith_set = {"add","sub","mul","div","addi","addw","subw","sll","srl","sra","slli","srli","srai","and","or","xor"}

    # create up to first 200 pseudocode lines
    import re

    reg_re = re.compile(r"x?\d+|[a-zA-Z]\w*")

    for ins in (report.instructions or [])[:200]:
        mn = (ins.get("mnemonic") or "").lower()
        op = ins.get("op_str") or ins.get("opstr") or ""
        addr = ins.get("address") or ins.get("addr") or ""

        ops = split_operands(op)

        # Helper to render register or immediate cleanly
        def clean(s):
            return s

        # Arithmetic immediate: addi rd, rs, imm -> rd = rs + imm
        if mn in {"addi","addiw","subi"} and len(ops) >= 3:
            rd, rs, imm = map(clean, ops[:3])
            pseudo.append(f"{addr}: {rd} = {rs} + {imm}")
        elif mn in {"add","sub","addw","subw"} and len(ops) >= 3:
            rd, rs1, rs2 = map(clean, ops[:3])
            op_sym = '+' if mn.startswith('add') else '-'
            pseudo.append(f"{addr}: {rd} = {rs1} {op_sym} {rs2}")
        elif mn in loads_set and len(ops) >= 2:
            # load rd, offset(base)
            rd = clean(ops[0])
            src = clean(ops[1])
            pseudo.append(f"{addr}: {rd} = MEM[{src}]")
        elif mn in stores_set and len(ops) >= 2:
            # store rs, offset(base)
            rs = clean(ops[0])
            dst = clean(ops[1])
            pseudo.append(f"{addr}: MEM[{dst}] = {rs}")
        elif mn in branch_set and len(ops) >= 3:
            rs1, rs2, target = map(clean, ops[:3])
            # translate to conditional
            pseudo.append(f"{addr}: IF {rs1} == {rs2} THEN GOTO {target}")
        elif mn in jump_set:
            if ops:
                rd = clean(ops[0])
                target = clean(ops[1]) if len(ops) > 1 else ''
                pseudo.append(f"{addr}: {rd} = RETURN_ADDR; GOTO {target}")
            else:
                pseudo.append(f"{addr}: JUMP")
        elif mn in arith_set and len(ops) >= 3:
            rd, rs1, rs2 = map(clean, ops[:3])
            pseudo.append(f"{addr}: {rd} = {rs1} OP {rs2}")
        elif mn:
            # fallback to raw mnemonic
            pseudo.append(f"{addr}: {mn.upper()} {op}")

    if not pseudo:
        pseudo = ["No pseudocode available"]

    report.pseudocode = pseudo

    # Build Control Flow Graph (CFG) from jump and branch instructions
    cfg_nodes = set()
    cfg_edges = []
    
    meta = report.metadata or {}
    entry_addr = meta.get("entry_point", "0x0")
    if entry_addr and entry_addr != "0x0":
        cfg_nodes.add(entry_addr)
    
    # Scan instructions for control flow targets
    for i, ins in enumerate(report.instructions or []):
        addr = ins.get("address") or ins.get("addr") or ""
        mn = (ins.get("mnemonic") or "").lower()
        op_str = ins.get("op_str") or ins.get("opstr") or ""
        
        # Add current instruction as a node
        if addr:
            cfg_nodes.add(str(addr))
        
        # Extract branch/jump targets
        if mn in {"beq","bne","blt","bge","bltu","bgeu"} and op_str:
            # For branch: extract target (usually last operand)
            ops = split_operands(op_str)
            if len(ops) >= 3:
                target = ops[-1].strip()
                if target and target != "0":
                    cfg_nodes.add(target)
                    if addr:
                        cfg_edges.append({"from": str(addr), "to": target, "type": "branch"})
                    # Also add fall-through to next instruction
                    if i + 1 < len(report.instructions or []):
                        next_addr = (report.instructions[i + 1].get("address") or 
                                    report.instructions[i + 1].get("addr") or "")
                        if next_addr:
                            cfg_edges.append({"from": str(addr), "to": str(next_addr), "type": "fall"})
        
        elif mn in {"jal","jalr"}:
            # For unconditional jumps: extract target
            ops = split_operands(op_str)
            if len(ops) >= 2:
                target = ops[-1].strip()
                if target and target != "0":
                    cfg_nodes.add(target)
                    if addr:
                        cfg_edges.append({"from": str(addr), "to": target, "type": "jump"})
        
        # Add edge to next instruction for non-terminal instructions
        elif mn not in {"jr","jalr"} and i + 1 < len(report.instructions or []):
            next_addr = (report.instructions[i + 1].get("address") or 
                        report.instructions[i + 1].get("addr") or "")
            if next_addr and addr:
                cfg_edges.append({"from": str(addr), "to": str(next_addr), "type": "seq"})
    
    # Store CFG in report
    report.cfg = {
        "entry_point": str(entry_addr),
        "nodes": list(cfg_nodes)[:50],  # Limit to 50 nodes for visualization
        "edges": cfg_edges[:100],  # Limit to 100 edges
        "node_count": len(cfg_nodes),
        "edge_count": len(cfg_edges)
    }

    # Build instruction hotspot heatmap (instruction frequency by type)
    instruction_freq = {}
    for ins in report.instructions or []:
        mn = (ins.get("mnemonic") or "unknown").lower()
        instruction_freq[mn] = instruction_freq.get(mn, 0) + 1
    
    # Sort by frequency and create heatmap data
    sorted_instrs = sorted(instruction_freq.items(), key=lambda x: x[1], reverse=True)
    max_freq = sorted_instrs[0][1] if sorted_instrs else 1
    
    # Create heatmap entries with normalized intensity (0-100)
    hotspots_data = []
    for mnemonic, count in sorted_instrs[:20]:  # Top 20 mnemonics
        intensity = int((count / max_freq) * 100)
        hotspots_data.append({
            "mnemonic": mnemonic,
            "count": count,
            "intensity": intensity,  # 0-100 for color intensity
            "percentage": round((count / (stats.get("total", 1) or 1)) * 100, 2)
        })
    
    report.instruction_hotspots = {
        "top_mnemonics": hotspots_data,
        "total_unique": len(instruction_freq),
        "max_frequency": max_freq
    }

    return report