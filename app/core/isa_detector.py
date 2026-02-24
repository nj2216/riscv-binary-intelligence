EXT_SIGNATURES = {
    "M": {"mul", "mulh", "div", "rem"},
    "A": {"lr.w", "sc.w", "amoadd.w"},
    "F": {"flw", "fadd.s"},
    "D": {"fld", "fadd.d"},
    "C": "c.",
    "V": "v"
}

def enrich(report):
    detected = set()

    for ins in report.instructions:
        m = ins["mnemonic"]

        for ext, sig in EXT_SIGNATURES.items():
            if isinstance(sig, set) and m in sig:
                detected.add(ext)
            elif isinstance(sig, str) and m in m.startswith(sig):
                detected.add(ext)

    report.isa_extensions = list(detected)
    return report