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
        self.instruction_summary: List[str] = []
        self.pseudocode: List[str] = []
        self.cfg: Dict[str, Any] = {}  # control flow graph: nodes and edges
        self.instruction_hotspots: Dict[str, Any] = {}  # instruction frequency heatmap data
        self.function_analysis: Dict[str, Any] = {}  # detected functions, boundaries, call graph
        self.execution_results: Dict[str, Any] = {}  # simulator execution stats

    def to_dict(self):
        total = self.instruction_stats.get("total", 1)

        percentages = {}
        for k, v in self.instruction_stats.items():
            if k != "total":
                percentages[k] = round(v / total * 100, 2)

        return {
            "metadata": self.metadata,
            "sections": self.sections,
            "instructions": self.instructions,
            "instruction_stats": self.instruction_stats,
            "instruction_percentages": percentages,
            "isa_extensions": self.isa_extensions,
            "heuristics": self.heuristics,
            "recommendations": self.recommendations,
            "instruction_summary": self.instruction_summary,
            "pseudocode": self.pseudocode,
            "cfg": self.cfg,
            "instruction_hotspots": self.instruction_hotspots,
            "function_analysis": self.function_analysis,
            "execution_results": self.execution_results,
        }