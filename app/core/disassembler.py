from capstone import *
from app.core.elf_parser import extract_text_selection

def enrich(report, file_bytes: bytes):
    text_info = extract_text_selection(file_bytes)

    text_bytes = text_info["bytes"]
    base_addr = text_info["addr"]
    bits = text_info["bits"]

    if bits == 64:
        md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
    else:
        md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)

    md.detail = False
    md.skipdata = True

    for insn in md.disasm(text_bytes, base_addr):
        report.instructions.append({
            "address": hex(insn.address),
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
            "size": insn.size
        })
    # count = 0
    # for insn in md.disasm(text_bytes, base_addr):
    #     print(hex(insn.address), insn.mnemonic, insn.op_str)
    #     count += 1

    # print("TOTAL:", count)
    
    return report