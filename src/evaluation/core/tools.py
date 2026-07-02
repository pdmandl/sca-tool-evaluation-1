# evaluation/core/tools.py

"""
Central registry for tool identifiers used in:
- filenames
- dumps
- analyses
- scripts

This avoids hard-coded or inconsistent tool naming.
"""

TOOL_FILE_IDS = {
    "Dependency-Track": "dtrack",
    "OSV": "osv",
    "GitHub": "github",
    "Snyk": "snyk",
    "Trivy": "trivy",
    "OSS Index": "ossindex",
    # NVD is a standalone completeness diagnostic, not a detection tool; the id
    # is registered here purely for filename / log consistency.
    "NVD": "nvd",
}


def tool_file_id(tool_name: str) -> str:
    """
    Return a stable, filesystem-safe identifier for a tool.

    Fallback:
      - lowercase
      - spaces replaced with '-'
    """
    if not tool_name:
        return "unknown"

    return TOOL_FILE_IDS.get(
        tool_name,
        tool_name.strip().lower().replace(" ", "-"),
    )
