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

    # Build a concise, human-readable instruction summary for UI/exports
    stats = report.instruction_stats or {}
    heur = report.heuristics or {}
    total = stats.get("total", 0)

    mi = float(heur.get("memory_intensity", 0) or 0)
    br = float(heur.get("branch_density", 0) or 0)
    ci = float(heur.get("compute_intensity", 0) or 0)
    rs = float(heur.get("risk_score", 0) or 0)

    report.instruction_summary = [
        f"Total instructions: {total}",
        f"Memory intensity: {mi:.3f}",
        f"Branch density: {br:.3f}",
        f"Compute intensity: {ci:.3f}",
        f"Risk score: {rs:.3f}",
    ]

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

    return report