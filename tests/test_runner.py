import subprocess
from pathlib import Path

import pytest

from egressdiff.runner import (
    CaptureError,
    cleanup,
    runtime_security,
    validate_report,
    write_json_atomic,
)


def inspect_data():
    return {
        "Config": {"User": "0:0"},
        "HostConfig": {
            "NetworkMode": "container:abc",
            "Privileged": False,
            "PidMode": "",
            "CapAdd": ["CAP_NET_RAW"],
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "ReadonlyRootfs": True,
        },
        "Mounts": [{"Destination": "/out"}],
    }


def valid_report():
    return {
        "security": {
            "uid": 0,
            "gid": 0,
            "CapInh": "0000000000000000",
            "CapPrm": "0000000000002000",
            "CapEff": "0000000000002000",
            "CapBnd": "0000000000002000",
            "NoNewPrivs": "1",
        },
        "runtime": runtime_security(inspect_data()),
        "compose_rc": 0,
        "smoke": {"rc": 0},
        "unknown": [],
    }


def test_runtime_security_uses_top_level_mounts() -> None:
    assert runtime_security(inspect_data())["mount_destinations"] == ["/out"]


def test_validate_report_accepts_net_raw_only() -> None:
    validate_report(valid_report())


def test_validate_report_rejects_extra_capability() -> None:
    report = valid_report()
    report["security"]["CapEff"] = "0000000000002001"
    with pytest.raises(CaptureError, match="CapEff"):
        validate_report(report)


def test_atomic_report_replaces_read_only_source(tmp_path) -> None:
    path = tmp_path / "capture.json"
    path.write_text("old\n", encoding="utf-8")
    path.chmod(0o444)
    write_json_atomic(path, {"status": "PASS"})
    assert path.read_text(encoding="utf-8").startswith("{")
    assert "PASS" in path.read_text(encoding="utf-8")
    assert not (tmp_path / "capture.json.tmp").exists()


def test_validate_report_preserves_unknown_as_result() -> None:
    report = valid_report()
    report["unknown"] = ["ipv6_unsupported"]
    validate_report(report)


def test_runtime_security_excludes_environment_secrets() -> None:
    data = inspect_data()
    data["Config"]["Env"] = ["SECRET_CANARY=egressdiff-canary"]
    assert "egressdiff-canary" not in str(runtime_security(data))


def test_cleanup_removes_project_images_before_inspect(monkeypatch) -> None:
    images = {"project-app"}
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[:3] == ["docker", "image", "rm"]:
            assert set(args[3:]) == images
            images.clear()
        stdout = ""
        if args[:3] == ["docker", "image", "ls"]:
            stdout = "".join(f"{image}\n" for image in sorted(images))
        return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

    monkeypatch.setattr("egressdiff.runner.run", fake_run)
    cleanup("project", Path("."), {}, set())
    assert any(args[:3] == ["docker", "image", "rm"] for args in calls)
    assert not images
