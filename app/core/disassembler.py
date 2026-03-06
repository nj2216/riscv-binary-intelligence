from capstone import *
from app.core.elf_parser import extract_text_selection

def enrich(report, file_bytes: bytes):
    text_info = extract_text_selection(file_bytes)

    text_bytes = text_info["bytes"]
    base_addr = text_info["addr"]
    bits = text_info["bits"]

    # Configure for RISC-V with compressed instruction support (RVC)
    if bits == 64:
        md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    else:
        md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)

    md.detail = True
    md.skipdata = True
    
    # Collect all instructions
    instructions = []
    mnemonic_counts = {}
    
    try:
        for insn in md.disasm(text_bytes, base_addr):
            instructions.append({
                "address": hex(insn.address),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "size": insn.size
            })
            # Track mnemonic frequency for debugging
            mnemonic_counts[insn.mnemonic] = mnemonic_counts.get(insn.mnemonic, 0) + 1
    except Exception as e:
        print(f"[Disassembler] Error during disassembly: {e}")
    
    # Store instructions in report
    report.instructions = instructions
    
    # Debug statistics - use same sets as classifier for consistency
    LOADS = {"lb","lh","lw","ld","lbu","lhu","lwu","c.ld","c.ldsp","c.lw","c.lwsp"}
    STORES = {"sb","sh","sw","sd","c.sd","c.sdsp","c.sw","c.swsp"}
    
    instruction_count = len(instructions)
    total_bytes = len(text_bytes)
    avg_size = total_bytes / (instruction_count + 1) if instruction_count > 0 else 0
    
    # Count memory operations
    loads = sum(1 for ins in instructions if ins["mnemonic"] in LOADS)
    stores = sum(1 for ins in instructions if ins["mnemonic"] in STORES)
    
    print(f"[Disassembler] Decoded {instruction_count} instructions from {total_bytes} bytes")
    print(f"[Disassembler] Average instruction size: {avg_size:.2f} bytes")
    print(f"[Disassembler] Memory ops detected: {loads} loads, {stores} stores")
    print(f"[Disassembler] Top mnemonics: {sorted(mnemonic_counts.items(), key=lambda x: x[1], reverse=True)[:10]}")
    
    return report