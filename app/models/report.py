from typing import List, Dict, Any


class BinaryReport:
    def __init__(self):
        self.metadata: Dict[str, Any] = {}
        self.sections: List[Dict[str, Any]] = []
        self.instructions: List[Dict[str, Any]] = []
        self.instruction_stats: Dict[str, Any] = {}
        self.isa_extensions: List[str] = []
        self.heuristics: Dict[str, Any] = {}
        self.recommendations: List[str] = []

    def to_dict(self):
        total = self.instruction_stats.get("total", 1)

        percentages = {}
        for k, v in self.instruction_stats.items():
            if k != "total":
                percentages[k] = round(v / total * 100, 2)

        return {
            "metadata": self.metadata,
            "sections": self.sections,
            "instruction_stats": self.instruction_stats,
            "instruction_percentages": percentages,
            "isa_extensions": self.isa_extensions,
            "heuristics": self.heuristics,
            "recommendations": self.recommendations,
        }