"""IVI 原厂 PoC 实验适配层（遗留批处理，不接入主扫描引擎）。"""

from .runner import discover_pocs, run_poc, run_batch, ExperimentResult

__all__ = ["discover_pocs", "run_poc", "run_batch", "ExperimentResult"]
