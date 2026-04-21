from pathlib import Path

from ground_truth_generation.gt_statistics import (
    _env_int_effective,
    compute_global_counts,
    compute_pre_balance_stats,
    write_statistics,
)


def _row(**kw):
    base = {
        "ecosystem": "pypi",
        "component_name": "django",
        "component_version": "3.2.0",
        "vulnerability_id": "OSV-1",
        "cve": "CVE-2024-1",
    }
    base.update(kw)
    return base


def test_env_int_effective(monkeypatch):
    monkeypatch.delenv("SOME_VAR", raising=False)
    assert _env_int_effective("SOME_VAR", 7) == (7, "default")
    monkeypatch.setenv("SOME_VAR", "")
    assert _env_int_effective("SOME_VAR", 7) == (7, "default")
    monkeypatch.setenv("SOME_VAR", "abc")
    assert _env_int_effective("SOME_VAR", 7) == (7, "default")
    monkeypatch.setenv("SOME_VAR", "42")
    assert _env_int_effective("SOME_VAR", 0) == (42, "env")


def test_compute_global_counts():
    rows = [
        _row(),
        _row(component_version="3.2.1", vulnerability_id="OSV-2"),
        _row(ecosystem="npm", component_name="lodash", vulnerability_id="OSV-3"),
    ]
    components, vulns = compute_global_counts(rows)
    assert components == 3
    assert vulns == 3


def test_compute_pre_balance_stats():
    rows = [
        _row(),
        _row(component_name="numpy", vulnerability_id="OSV-2", cve=None),
        _row(ecosystem="npm", component_name="lodash", vulnerability_id="OSV-3"),
    ]
    out = compute_pre_balance_stats(rows)
    assert out["pypi"]["osv_vuln_entries"] == 2
    assert out["pypi"]["unique_cves"] == 1
    assert out["npm"]["unique_components"] == 1


def test_write_statistics(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SAMPLES", "100")
    monkeypatch.setenv("ECOSYSTEMS", "pypi npm")
    monkeypatch.setenv("BALANCE", "1")
    monkeypatch.setenv("BALANCE_STRATEGY", "min")

    rows = [
        _row(),
        _row(component_version="3.2.1", vulnerability_id="OSV-2"),
        _row(component_name="numpy", vulnerability_id="OSV-3", cve=None),
        _row(ecosystem="npm", component_name="lodash", vulnerability_id="OSV-4"),
        _row(
            ecosystem="npm",
            component_name="lodash",
            component_version="4.17.11",
            vulnerability_id="OSV-5",
        ),
    ]
    csv_path = tmp_path / "gt.csv"
    csv_path.write_text("")
    sbom_path = tmp_path / "gt.sbom.json"
    sbom_path.write_text("{}")
    out_path = tmp_path / "gt.stat.txt"

    write_statistics(
        rows=rows,
        out_path=out_path,
        csv_path=csv_path,
        sbom_path=sbom_path,
        pre_balance_stats=compute_pre_balance_stats(rows),
        balance_stats={"pypi": {"kept_rows": 3}, "npm": {"kept_rows": 2}},
    )
    text = out_path.read_text()
    assert "OSV Ground Truth Dataset" in text
    assert "Per-ecosystem statistics" in text
    assert "Top-20 components" in text
    assert "API access statistics" in text
