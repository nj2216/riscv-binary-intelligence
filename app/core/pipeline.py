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
    report = instruction_classifier.enrich(report)
    report = isa_detector.enrich(report)
    report = heuristics.enrich(report)

    return report