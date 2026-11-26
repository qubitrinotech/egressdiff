import json

from egressdiff.cli import main
from egressdiff.diff import make_diff


def report(candidate: bool = False, unknown=None):
    return {
        "service": "app",
        "events": {
            "dns": ["db.example"] + (["telemetry.example"] if candidate else []),
            "tcp": ["172.31.0.10:8000"] + (["172.31.0.20:9443"] if candidate else []),
            "tls_sni": ["telemetry.example@172.31.0.20:9443"] if candidate else [],
        },
        "unknown": unknown or [],
    }


def test_diff_has_exactly_one_aggregated_new_destination() -> None:
    result = make_diff(report(), report(candidate=True))
    assert result["verdict"] == "REVIEW_REQUIRED"
    assert result["removed"] == []
    assert [item["key"] for item in result["new"]] == ["tls-sni://telemetry.example:9443"]
    assert result["new"][0]["evidence"] == ["DNS", "TCP", "TLS-SNI"]
    assert json.dumps(result, sort_keys=True) == json.dumps(
        make_diff(report(), report(candidate=True)), sort_keys=True
    )


def test_unknown_drives_unknown_verdict() -> None:
    result = make_diff(report(), report(candidate=True, unknown=["ipv4_fragment"]))
    assert result["verdict"] == "UNKNOWN"


def test_cli_diff_writes_json_and_markdown(tmp_path, monkeypatch, capsys) -> None:
    baseline = tmp_path / "baseline.json"
    candidate = tmp_path / "candidate.json"
    baseline.write_text(json.dumps(report()), encoding="utf-8")
    candidate.write_text(json.dumps(report(candidate=True)), encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv",
        [
            "egressdiff",
            "diff",
            "--baseline",
            str(baseline),
            "--candidate",
            str(candidate),
            "--out",
            str(tmp_path / "out"),
        ],
    )
    assert main() == 0
    assert "NEW" in (tmp_path / "out" / "diff.md").read_text(encoding="utf-8")
    assert "VERDICT=REVIEW_REQUIRED" in capsys.readouterr().out
    written = json.loads((tmp_path / "out" / "diff.json").read_text(encoding="utf-8"))
    assert len(written["new"]) == 1
