from pathlib import Path

from evaluation.core.model import Finding
from evaluation.reporting.dump_tool_findings import dump_tool_findings_csv
from evaluation.reporting.tool_findings_txt import write_tool_findings_txt


def _f(**kw):
    base = dict(ecosystem="pypi", component="django", version="3.2.0")
    base.update(kw)
    return Finding(**base)


class TestToolFindingsTxt:
    def test_writes_file(self, tmp_path: Path):
        findings = [
            _f(cve="CVE-1", ghsa="GHSA-x", osv_id="OSV-1",
               affected_version_range=">=1,<2", source="osv"),
            _f(component="numpy", version="2.0"),
        ]
        path = write_tool_findings_txt(
            out_dir=tmp_path, ground_truth_name="gt",
            tool="osv", run_id="r1", findings=findings,
        )
        text = path.read_text()
        assert "Tool Findings" in text
        assert "django" in text and "numpy" in text
        assert "osv" in text

    def test_empty_findings(self, tmp_path: Path):
        path = write_tool_findings_txt(
            out_dir=tmp_path, ground_truth_name="gt",
            tool="osv", run_id="r1", findings=[],
        )
        assert path.exists()


class TestDumpToolFindingsCsv:
    def test_dump(self, tmp_path: Path):
        gt_csv = tmp_path / "gt.csv"
        gt_csv.write_text("a,b\n1,2\n")
        findings = [_f(cve="CVE-1", osv_id="OSV-1", description="descr")]
        out = dump_tool_findings_csv(
            tool_name="OSV", tool_findings=findings,
            ground_truth_csv=str(gt_csv),
        )
        assert out.exists()
        text = out.read_text()
        assert "django" in text and "CVE-1" in text
