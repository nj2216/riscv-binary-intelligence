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

    return report