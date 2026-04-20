"""Smoke imports: exercise module-level code for otherwise-untested modules.

Each import runs the module's top-level statements (imports, class/function
defs, constants). This establishes a baseline coverage floor for modules we
don't exercise with unit tests.
"""


def test_import_ecosystems_collectors():
    # Module-level constants + function signatures
    from ground_truth_generation.ecosystems import maven  # noqa: F401
    from ground_truth_generation.ecosystems import npm  # noqa: F401
    from ground_truth_generation.ecosystems import nuget  # noqa: F401
    from ground_truth_generation.ecosystems import pypi  # noqa: F401


def test_import_plots():
    from evaluation.analysis import plots  # noqa: F401


def test_import_reporting():
    from evaluation.reporting import evaluation_report  # noqa: F401


def test_import_temporal_runner():
    from evaluation import temporal_runner  # noqa: F401


def test_import_evaluate():
    from evaluation import evaluate  # noqa: F401


def test_import_build_multi_gt():
    from ground_truth_generation import build_multi_ground_truth_dataset  # noqa: F401
