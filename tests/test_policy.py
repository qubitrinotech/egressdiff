import json

import pytest

from egressdiff.cli import main
from egressdiff.diff import make_diff, markdown, write_diff
from egressdiff.policy import apply_policy, approve_key, load_policy

KEY = "tls-sni://telemetry.example:9443"


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


def raw_diff(unknown=None):
    return make_diff(report(), report(candidate=True, unknown=unknown))


def invoke(monkeypatch, args: list[str]) -> int:
    monkeypatch.setattr("sys.argv", ["egressdiff", *args])
    return main()


def test_apply_policy_marks_exact_new_key_approved() -> None:
    result = apply_policy(raw_diff(), [KEY])
    assert result["verdict"] == "PASS"
    assert result["approved_keys"] == [KEY]
    assert result["unapproved_keys"] == []
    assert len(result["new"]) == 1
    assert "**NEW APPROVED**" in markdown(result)


def test_unknown_remains_unknown_after_approval() -> None:
    result = apply_policy(raw_diff(["ipv4_fragment"]), [KEY])
    assert result["verdict"] == "UNKNOWN"
    assert result["approved_keys"] == [KEY]
    assert result["unapproved_keys"] == []


def test_approve_writes_policy_and_is_idempotent(tmp_path) -> None:
    path = tmp_path / "policy.json"
    assert approve_key(raw_diff(), path, KEY) == [KEY]
    first = path.read_bytes()
    assert approve_key(raw_diff(), path, KEY) == [KEY]
    assert path.read_bytes() == first
    assert json.loads(first) == {"schema_version": 1, "approved_keys": [KEY]}


def test_approve_rejects_key_outside_new(tmp_path) -> None:
    path = tmp_path / "policy.json"
    with pytest.raises(ValueError, match="not in NEW"):
        approve_key(raw_diff(), path, "tls-sni://ghost.example:443")
    assert not path.exists()


def test_policy_rejects_duplicate_keys(tmp_path) -> None:
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps({"schema_version": 1, "approved_keys": [KEY, KEY]}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicates"):
        load_policy(path)


def test_cli_check_before_and_after_approve(tmp_path, monkeypatch) -> None:
    raw_path = tmp_path / "raw" / "diff.json"
    write_diff(raw_diff(), raw_path.parent)
    policy = tmp_path / "policy.json"
    before = tmp_path / "before"
    after = tmp_path / "after"

    assert (
        invoke(
            monkeypatch,
            ["check", "--diff", str(raw_path), "--policy", str(policy), "--out", str(before)],
        )
        == 1
    )
    before_result = json.loads((before / "diff.json").read_text(encoding="utf-8"))
    assert before_result["verdict"] == "REVIEW_REQUIRED"
    assert before_result["unapproved_keys"] == [KEY]
    assert not policy.exists()

    assert (
        invoke(
            monkeypatch,
            ["approve", "--diff", str(raw_path), "--key", KEY, "--policy", str(policy)],
        )
        == 0
    )
    assert (
        invoke(
            monkeypatch,
            ["check", "--diff", str(raw_path), "--policy", str(policy), "--out", str(after)],
        )
        == 0
    )
    after_result = json.loads((after / "diff.json").read_text(encoding="utf-8"))
    assert after_result["verdict"] == "PASS"
    assert after_result["approved_keys"] == [KEY]
    assert after_result["unapproved_keys"] == []
    assert "**NEW APPROVED**" in (after / "diff.md").read_text(encoding="utf-8")


def test_cli_check_unknown_returns_two(tmp_path, monkeypatch) -> None:
    diff = raw_diff(["ipv4_fragment"])
    raw_path = tmp_path / "raw" / "diff.json"
    write_diff(diff, raw_path.parent)
    policy = tmp_path / "policy.json"
    approve_key(diff, policy, KEY)

    assert (
        invoke(
            monkeypatch,
            [
                "check",
                "--diff",
                str(raw_path),
                "--policy",
                str(policy),
                "--out",
                str(tmp_path / "check"),
            ],
        )
        == 2
    )
