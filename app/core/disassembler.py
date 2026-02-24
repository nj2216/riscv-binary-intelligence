from capstone import *

def enrich(report, file_bytes: bytes):
    md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)

    # We must properly extract .text section later
    # For now assume we get text_bytes & base_addr
    text_bytes = b""
    base_addr = 0x0

    for insn in md.disasm(text_bytes, base_addr):
        report.instructions.append({
            "address": hex(insn.address),
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str
        })
    
    return report