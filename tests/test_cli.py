import pytest
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


def test_empty_file_does_not_run_samples(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    p = tmp_path / "empty.txt"
    p.write_text("", encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        main.main(["--file", str(p), "--no-charts"])
    assert e.value.code == 2
    err = capsys.readouterr()
    assert "is empty" in err.err and "Spear Phishing" not in err.out
    assert not (tmp_path / "output").exists()


def test_empty_text_is_an_error(capsys):
    with pytest.raises(SystemExit) as e:
        main.main(["--text", "   "])
    assert e.value.code == 2


def test_missing_file_is_a_clean_error(tmp_path, capsys):
    with pytest.raises(SystemExit) as e:
        main.main(["--file", str(tmp_path / "nope.txt")])
    assert e.value.code == 2
    assert "cannot read --file" in capsys.readouterr().err


def test_json_without_input_explains(capsys):
    with pytest.raises(SystemExit) as e:
        main.main(["--json"])
    assert e.value.code == 2
    assert "--json works on one message" in capsys.readouterr().err


def test_json_reports_hidden_characters(capsys):
    assert main.main(["--text", "URG​ENT: act now", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["hidden_characters"] == 1 and "urgent" in data["vectors"]["urgency"]["matched_keywords"]
