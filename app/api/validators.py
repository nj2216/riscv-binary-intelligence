from typing import Dict, Any


REQUIRED_KEYS = {
    "metadata",
    "sections",
    "instruction_stats",
    "instruction_percentages",
    "isa_extensions",
    "heuristics",
    "recommendations",
}


def validate_report_schema(report: Dict[str, Any]) -> None:
    """Validate that the report dict contains the expected top-level keys.

    Raises ValueError with a helpful message if keys are missing or the shape is wrong.
    """
    if not isinstance(report, dict):
        raise ValueError("report must be a dict")

    missing = REQUIRED_KEYS - set(report.keys())
    if missing:
        raise ValueError(f"report is missing required keys: {', '.join(sorted(missing))}")

    # Basic checks for types
    if not isinstance(report.get("sections"), list):
        raise ValueError("report.sections must be a list")
    if not isinstance(report.get("instruction_stats"), dict):
        raise ValueError("report.instruction_stats must be a dict")
    if not isinstance(report.get("instruction_percentages"), dict):
        raise ValueError("report.instruction_percentages must be a dict")
