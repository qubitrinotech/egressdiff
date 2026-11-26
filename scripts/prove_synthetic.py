from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

KEY = "tls-sni://telemetry.example:9443"
CANARY = "egressdiff-secret-canary-7f3c9d"
EXPECTED_LIMITATIONS = {
    "dns_loopback_attribution_single_app_only",
    "single_app_service_only",
    "smoke_executed_paths_only",
}
LOG_OUTPUTS: list[str] = []


def run(command: list[str], cwd: Path, *, expected_rc: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
        stdin=subprocess.DEVNULL,
    )
    LOG_OUTPUTS.extend([result.stdout, result.stderr])
    if result.returncode != expected_rc:
        raise RuntimeError(
            f"{' '.join(command)}: rc={result.returncode}, expected={expected_rc}; "
            f"{result.stdout}{result.stderr}"
        )
    return result


def capture_command(repo: Path, root: Path, variant: str) -> list[str]:
    return [
        sys.executable,
        "-m",
        "egressdiff",
        "capture",
        "--fixture-dir",
        str(repo / "fixtures/synthetic"),
        "--variant",
        variant,
        "--out",
        str(root / variant),
    ]


def capture(repo: Path, root: Path, variant: str) -> dict[str, object]:
    run(capture_command(repo, root, variant), repo)
    return json.loads((root / variant / "capture.json").read_text(encoding="utf-8"))


def capture_and_diff(repo: Path, root: Path) -> bytes:
    reports = {}
    for variant in ("baseline", "candidate"):
        reports[variant] = capture(repo, root, variant)
        if reports[variant]["unknown"]:
            raise RuntimeError(f"unknown entries in {variant}")
    diff_out = root / "diff"
    run(
        [
            sys.executable,
            "-m",
            "egressdiff",
            "diff",
            "--baseline",
            str(root / "baseline" / "capture.json"),
            "--candidate",
            str(root / "candidate" / "capture.json"),
            "--out",
            str(diff_out),
        ],
        repo,
    )
    result = json.loads((diff_out / "diff.json").read_text(encoding="utf-8"))
    if result["verdict"] != "REVIEW_REQUIRED":
        raise RuntimeError(f"verdict={result['verdict']}")
    if result["removed"] or len(result["new"]) != 1:
        raise RuntimeError(f"new/removed mismatch: {result}")
    new = result["new"][0]
    if new["key"] != KEY:
        raise RuntimeError(f"unexpected NEW destination: {new}")
    if set(new["evidence"]) != {"DNS", "TCP", "TLS-SNI"}:
        raise RuntimeError(f"incomplete evidence: {new}")
    return (diff_out / "diff.json").read_bytes()


def check_diff(
    repo: Path,
    diff_path: Path,
    policy: Path,
    out: Path,
    *,
    expected_rc: int,
    expected_verdict: str,
) -> dict[str, object]:
    run(
        [
            sys.executable,
            "-m",
            "egressdiff",
            "check",
            "--diff",
            str(diff_path),
            "--policy",
            str(policy),
            "--out",
            str(out),
        ],
        repo,
        expected_rc=expected_rc,
    )
    result = json.loads((out / "diff.json").read_text(encoding="utf-8"))
    if result["verdict"] != expected_verdict:
        raise RuntimeError(f"check verdict={result['verdict']}, expected={expected_verdict}")
    return result


def matching_projects(repo: Path, prefix: str) -> set[str]:
    result = run(
        [
            "docker",
            "ps",
            "-a",
            "--format",
            '{{.ID}} {{.Label "com.docker.compose.project"}}',
        ],
        repo,
    )
    projects = set()
    for line in result.stdout.splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) == 2 and parts[1].startswith(prefix):
            projects.add(parts[1])
    return projects


def project_resources(repo: Path, project: str) -> dict[str, list[str]]:
    containers = run(
        ["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}"],
        repo,
    ).stdout.split()
    networks = run(
        [
            "docker",
            "network",
            "ls",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={project}",
        ],
        repo,
    ).stdout.split()
    images = run(
        ["docker", "image", "ls", "-q", "--filter", f"reference={project}-*"],
        repo,
    ).stdout.split()
    return {"containers": containers, "networks": networks, "images": images}


def force_cleanup(repo: Path, project: str, out: Path) -> None:
    fixture = repo / "fixtures/synthetic"
    env = os.environ.copy()
    env.update(VARIANT="sigint", OUT_DIR=str(out))
    commands = [
        ["docker", "compose", "-p", project, "down", "--volumes", "--remove-orphans"],
        ["docker", "image", "ls", "-q", "--filter", f"reference={project}-*"],
    ]
    for command in commands:
        result = subprocess.run(
            command,
            cwd=fixture,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            stdin=subprocess.DEVNULL,
            timeout=90,
        )
        LOG_OUTPUTS.extend([result.stdout, result.stderr])
        if command[1] == "image" and result.stdout.split():
            removal = subprocess.run(
                ["docker", "image", "rm", *result.stdout.split()],
                cwd=fixture,
                env=env,
                text=True,
                capture_output=True,
                check=False,
                stdin=subprocess.DEVNULL,
                timeout=90,
            )
            LOG_OUTPUTS.extend([removal.stdout, removal.stderr])


def sigint_capture(repo: Path, root: Path) -> None:
    out = root / "sigint"
    root.mkdir(parents=True, exist_ok=True)
    log_path = root / "sigint.log"
    process = None
    prefix = None
    try:
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.Popen(
                capture_command(repo, root, "sigint"),
                cwd=repo,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            prefix = f"egressdiff-f11-{process.pid}-sigint-"
            deadline = time.monotonic() + 90
            while not (out / "capture.ready").exists():
                if process.poll() is not None:
                    raise RuntimeError("sigint capture exited before capture.ready")
                if time.monotonic() >= deadline:
                    raise RuntimeError("timeout waiting for capture.ready during SIGINT")
                time.sleep(0.1)
            projects = matching_projects(repo, prefix)
            if len(projects) != 1:
                raise RuntimeError(f"SIGINT projects={sorted(projects)}")
            project = next(iter(projects))
            process.send_signal(signal.SIGINT)
            process.wait(timeout=180)
        LOG_OUTPUTS.append(log_path.read_text(encoding="utf-8"))
        if process.returncode == 0:
            raise RuntimeError("SIGINT capture unexpectedly returned 0")
        resources = project_resources(repo, project)
        if any(resources.values()):
            raise RuntimeError(f"SIGINT cleanup: {resources}")
    except BaseException:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        if prefix is not None:
            for stale_project in matching_projects(repo, prefix):
                force_cleanup(repo, stale_project, out)
        raise


def assert_no_canary(root: Path) -> None:
    for path in root.rglob("*"):
        if (
            path.is_file()
            and path.suffix in {".json", ".md", ".log"}
            and CANARY.encode("ascii") in path.read_bytes()
        ):
            raise RuntimeError(f"canary found in {path}")
    for output in LOG_OUTPUTS:
        if CANARY in output:
            raise RuntimeError("canary found in captured logs")


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    os.environ["EGRESSDIFF_TEST_CANARY"] = CANARY
    with tempfile.TemporaryDirectory(prefix="egressdiff-f13-proof-") as tmp:
        root = Path(tmp)
        policy = root / "policy.json"
        round1 = root / "round1"
        first = capture_and_diff(repo, round1)
        before = check_diff(
            repo,
            round1 / "diff" / "diff.json",
            policy,
            round1 / "check-before",
            expected_rc=1,
            expected_verdict="REVIEW_REQUIRED",
        )
        if before["unapproved_keys"] != [KEY] or before["approved_keys"]:
            raise RuntimeError(f"A1 policy keys: {before}")
        run(
            [
                sys.executable,
                "-m",
                "egressdiff",
                "approve",
                "--diff",
                str(round1 / "diff" / "diff.json"),
                "--key",
                KEY,
                "--policy",
                str(policy),
            ],
            repo,
        )
        round2 = root / "round2"
        second = capture_and_diff(repo, round2)
        if first != second:
            raise RuntimeError("normalized diff is unstable between captures")
        after = check_diff(
            repo,
            round2 / "diff" / "diff.json",
            policy,
            round2 / "check-after",
            expected_rc=0,
            expected_verdict="PASS",
        )
        if after["approved_keys"] != [KEY] or after["unapproved_keys"]:
            raise RuntimeError(f"A2 policy keys: {after}")
        if "**NEW APPROVED**" not in (round2 / "check-after" / "diff.md").read_text(
            encoding="utf-8"
        ):
            raise RuntimeError("A2 Markdown does not contain NEW APPROVED")

        negative_root = root / "negative"
        negative = capture(repo, negative_root, "negative")
        expected_unknown = {
            "ipv6_unsupported",
            "multi_service_unsupported:worker",
            "udp_unsupported:172.31.0.20:443",
        }
        if not expected_unknown.issubset(set(negative["unknown"])):
            raise RuntimeError(f"negative unknown={negative['unknown']}")
        if negative["events"]["tcp"] != ["172.31.0.10:8000"]:
            raise RuntimeError(f"direct-IP events={negative['events']}")
        if negative["events"]["dns"] or negative["events"]["tls_sni"]:
            raise RuntimeError(
                f"negative capture unexpectedly contains DNS/TLS: {negative['events']}"
            )
        if set(negative["capture_limitations"]) != EXPECTED_LIMITATIONS:
            raise RuntimeError(f"limitations={negative['capture_limitations']}")
        negative_diff = negative_root / "diff"
        run(
            [
                sys.executable,
                "-m",
                "egressdiff",
                "diff",
                "--baseline",
                str(round1 / "baseline" / "capture.json"),
                "--candidate",
                str(negative_root / "negative" / "capture.json"),
                "--out",
                str(negative_diff),
            ],
            repo,
        )
        check_diff(
            repo,
            negative_diff / "diff.json",
            root / "negative-policy.json",
            negative_root / "check",
            expected_rc=2,
            expected_verdict="UNKNOWN",
        )

        failure_root = root / "failure"
        failure = run(
            capture_command(repo, failure_root, "failure"),
            repo,
            expected_rc=1,
        )
        if "compose/smoke failed" not in failure.stdout:
            raise RuntimeError(f"failure output={failure.stdout}{failure.stderr}")
        if "additional cleanup failure" in failure.stdout:
            raise RuntimeError(f"failure cleanup output={failure.stdout}")
        failure_report = json.loads(
            (failure_root / "failure" / "capture.json").read_text(encoding="utf-8")
        )
        if failure_report["smoke"]["status"] != "FAIL":
            raise RuntimeError(f"failure smoke={failure_report['smoke']}")

        sigint_capture(repo, root / "sigint-proof")
        assert_no_canary(root)
    print("NEW_COUNT=1")
    print(f"NEW_DESTINATION={KEY}")
    print("EVIDENCE=DNS,TCP,TLS-SNI")
    print("CHECK_BEFORE_RC=1")
    print("CHECK_AFTER_RC=0")
    print("CHECK_NEGATIVE_RC=2")
    print(f"APPROVED={KEY}")
    print("DIRECT_IP_OBSERVED=172.31.0.10:8000")
    print("QUIC_UDP_UNKNOWN=172.31.0.20:443")
    print("IPV6_UNKNOWN=1")
    print("MULTI_SERVICE_UNKNOWN=worker")
    print("CAPTURES=7")
    print("DIFF_STABLE=1")
    print("CLEANUP_OK=1")
    print("A1_OK=1")
    print("A2_OK=1")
    print("A3_OK=1")
    print("A4_SUCCESS_OK=1")
    print("A4_FAILURE_OK=1")
    print("A4_SIGINT_OK=1")
    print("A5_REDACTION_OK=1")
    print("A6_UNKNOWN_OK=1")
    print("D002_COVERAGE_OK=1")
    print("SYNTHETIC_PROOF_OK=1")
    print("F12_SYNTHETIC_PROOF_OK=1")
    print("F13_SYNTHETIC_PROOF_OK=1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
