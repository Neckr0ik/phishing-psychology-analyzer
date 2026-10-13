import json

import main


def test_batch(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main.main([]) == 0
    report = (tmp_path / "output" / "analysis_report.md").read_text(encoding="utf-8")
    assert "does not prove" in report and "T1566" in report
    assert (tmp_path / "output" / "heatmap_vectors.png").exists()


def test_json_from_file(tmp_path, capsys):
    p = tmp_path / "mail.txt"
    p.write_text("Congratulations! You won a free prize. Claim now, offer expires today.", encoding="utf-8")
    assert main.main(["--file", str(p), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["risk_level"] in {"MEDIUM", "HIGH", "CRITICAL"}
    assert "reciprocity" in data["dominant_vectors"]
    assert data["vectors"]["reciprocity"]["matched_keywords"]


def test_text_no_charts(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main.main(["--text", "Please review the attached agenda.", "--no-charts"]) == 0
    assert not (tmp_path / "output").exists()
