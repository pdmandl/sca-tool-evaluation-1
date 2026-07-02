"""
NVD CPE-data completeness diagnostic.

This package holds the deterministic, I/O-free core of the NVD completeness
diagnostic described in
``knowledge/prds/prd-nvd-completeness-diagnostic.md``:

- :mod:`evaluation.nvd_completeness.record` — a small typed view of an NVD CVE
  record (its CVE id and flattened CPE configuration nodes) plus the parser that
  turns a raw NVD 2.0 API body into that view.
- :mod:`evaluation.nvd_completeness.coverage` — the single classification seam,
  ``classify_nvd_coverage``, the generous within-CVE product matcher, and the
  greppable per-observation log line.
- :mod:`evaluation.nvd_completeness.report` — per-ecosystem aggregation of the
  coverage buckets into the ``*_nvd_completeness`` report.

The live ``nvd`` adapter (HTTP transport, rate limiting) and the runner entry
point that drives these functions against live NVD are the walking-skeleton
deliverables tracked separately; nothing here performs I/O.
"""

from evaluation.nvd_completeness.coverage import (
    COVERAGE_BUCKETS,
    CVE_ABSENT,
    MATCH_EXACT,
    MATCH_SUBSTRING,
    NO_CPE_CONFIG,
    NO_CVE,
    PRODUCT_MATCHED,
    PRODUCT_MISMATCH,
    classify_nvd_coverage,
    component_tokens,
    format_coverage_log_line,
    log_coverage_observation,
    node_product_match,
)
from evaluation.nvd_completeness.record import (
    NvdCpeNode,
    ParsedNvdRecord,
    parse_nvd_record,
)
from evaluation.nvd_completeness.report import (
    NvdCompletenessReport,
    aggregate_buckets,
    render_report,
)

__all__ = [
    "COVERAGE_BUCKETS",
    "CVE_ABSENT",
    "MATCH_EXACT",
    "MATCH_SUBSTRING",
    "NO_CPE_CONFIG",
    "NO_CVE",
    "PRODUCT_MATCHED",
    "PRODUCT_MISMATCH",
    "classify_nvd_coverage",
    "component_tokens",
    "format_coverage_log_line",
    "log_coverage_observation",
    "node_product_match",
    "NvdCpeNode",
    "ParsedNvdRecord",
    "parse_nvd_record",
    "NvdCompletenessReport",
    "aggregate_buckets",
    "render_report",
]
