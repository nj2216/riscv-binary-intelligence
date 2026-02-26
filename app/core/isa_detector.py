from collections import defaultdict

EXT_SIGNATURES = {
    "M": {"mul", "mulh", "mulhu", "mulhsu", "div", "divu", "rem", "remu"},
    "A": {"lr.w", "sc.w", "amoswap.w", "amoadd.w"},
    "F": {"flw", "fsw", "fadd.s", "fsub.s", "fmul.s", "fdiv.s"},
    "D": {"fld", "fsd", "fadd.d", "fsub.d", "fmul.d", "fdiv.d"},
}

PREFIX_SIGNATURES = {
    "C": "c.",
    "V": "v",
}

def detect_extensions(report):
    detected = set()
    extension_counts = defaultdict(int)

    for ins in report.instructions:
        mnemonic = ins.get("mnemonic", "").lower()

        # Exact matches
        for ext, signatures in EXT_SIGNATURES.items():
            if mnemonic in signatures:
                detected.add(ext)
                extension_counts[ext] += 1

        # Prefix matches
        for ext, prefix in PREFIX_SIGNATURES.items():
            if mnemonic.startswith(prefix):
                detected.add(ext)
                extension_counts[ext] += 1

    return detected, extension_counts

def detect_from_stats(report, detected, extension_counts):
    stats = getattr(report, "instruction_stats", {})

    if stats.get("compressed", 0) > 0:
        detected.add("C")
        extension_counts["C"] += stats["compressed"]

    if stats.get("mul_div", 0) > 0:
        detected.add("M")
        extension_counts["M"] += stats["mul_div"]

    if stats.get("floating", 0) > 0:
        detected.add("F")
        extension_counts["F"] += stats["floating"]

    return detected, extension_counts

def compute_confidence(extension_counts, total_instructions):
    confidence = {}

    for ext, count in extension_counts.items():
        if total_instructions == 0:
            confidence[ext] = 0.0
        else:
            confidence[ext] = round(count / total_instructions, 3)

    return confidence

def synthesize_arch_string(bits, extensions):
    base = "rv64" if bits == 64 else "rv32"
    ext_string = "".join(sorted(e.lower() for e in extensions))
    return base + ext_string

def enrich(report):
    total = len(report.instructions)
    

    detected, extension_counts = detect_extensions(report)
    detected, extension_counts = detect_from_stats(
        report, detected, extension_counts
    )

    confidence = compute_confidence(extension_counts, total)
    base = "RV64" if report.metadata.get("bits") == 64 else "RV32"
    detected.add("I")

    report.isa_extensions = sorted(list(detected))
    report.metadata["extension_confidence"] = confidence
    report.metadata["arch_string"] = synthesize_arch_string(
        report.metadata.get("bits", 32),
        report.isa_extensions
    )

    return report