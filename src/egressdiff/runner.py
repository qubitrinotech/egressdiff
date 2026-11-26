from __future__ import annotations

import json
import os
import subprocess
import uuid
from pathlib import Path

CAP_NET_RAW = 1 << 13
SUPPORTED_FIXTURE_SERVICES = {"app", "capture", "db", "telemetry"}


class CaptureError(Exception):
    pass


def run(
    args: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: int = 60,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            args,
            cwd=cwd,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise CaptureError(f"command timed out: {' '.join(args)}") from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise CaptureError(f"{' '.join(args)}: {detail[-5000:] or f'rc={result.returncode}'}")
    return result


def runtime_security(data: dict[str, object]) -> dict[str, object]:
    host = data["HostConfig"]
    return {
        "user": data["Config"]["User"],
        "network_mode": host["NetworkMode"],
        "privileged": host["Privileged"],
        "pid_mode": host["PidMode"],
        "cap_add": host["CapAdd"],
        "cap_drop": host["CapDrop"],
        "security_opt": host["SecurityOpt"],
        "readonly_rootfs": host["ReadonlyRootfs"],
        "mount_destinations": [mount["Destination"] for mount in data["Mounts"]],
    }


def write_json_atomic(path: Path, value: dict[str, object]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def validate_report(report: dict[str, object]) -> None:
    security = report["security"]
    runtime = report["runtime"]
    errors = []
    if int(security["CapInh"], 16) != 0:
        errors.append("CapInh != 0")
    for field in ("CapPrm", "CapEff", "CapBnd"):
        if int(security[field], 16) != CAP_NET_RAW:
            errors.append(f"{field}={security[field]}")
    if security["uid"] != 0 or security["gid"] != 0:
        errors.append("capture is not UID/GID 0")
    if security["NoNewPrivs"] != "1" or not runtime["readonly_rootfs"]:
        errors.append("no-new-privileges/read-only rootfs is missing")
    if runtime["privileged"] or runtime["pid_mode"] == "host":
        errors.append("privileged/host PID")
    if not str(runtime["network_mode"]).startswith("container:"):
        errors.append("capture does not share the app network namespace")
    if runtime["user"] != "0:0":
        errors.append("unexpected runtime user")
    if runtime["cap_add"] != ["CAP_NET_RAW"] or runtime["cap_drop"] != ["ALL"]:
        errors.append("unexpected runtime capabilities")
    if runtime["mount_destinations"] != ["/out"]:
        errors.append("unexpected mount destinations")
    if report["compose_rc"] != 0 or report["smoke"].get("rc") != 0:
        errors.append("compose/smoke failed")
    if errors:
        raise CaptureError("; ".join(errors))


def cleanup(project: str, cwd: Path, env: dict[str, str], image_ids: set[str]) -> None:
    run(
        ["docker", "compose", "-p", project, "down", "--volumes", "--remove-orphans"],
        cwd=cwd,
        env=env,
        timeout=90,
        check=False,
    )
    project_images = set(
        run(
            ["docker", "image", "ls", "-q", "--filter", f"reference={project}-*"],
            cwd=cwd,
            env=env,
            check=False,
        ).stdout.split()
    )
    images_to_remove = image_ids | project_images
    if images_to_remove:
        run(["docker", "image", "rm", *sorted(images_to_remove)], cwd=cwd, env=env, check=False)
    containers = run(
        ["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}"],
        cwd=cwd,
        env=env,
        check=False,
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
        cwd=cwd,
        env=env,
        check=False,
    ).stdout.split()
    images = run(
        ["docker", "image", "ls", "-q", "--filter", f"reference={project}-*"],
        cwd=cwd,
        env=env,
        check=False,
    ).stdout.split()
    if containers or networks or images:
        raise CaptureError(
            f"cleanup: containers={containers}, networks={networks}, images={images}"
        )


def capture_fixture(fixture: Path, variant: str, out: Path) -> dict[str, object]:
    if variant not in {"baseline", "candidate", "negative", "failure", "sigint"}:
        raise CaptureError("unknown synthetic variant")
    fixture = fixture.resolve()
    out = out.resolve()
    compose = fixture / "compose.yaml"
    if not compose.is_file():
        raise CaptureError(f"fixture Compose file not found: {compose}")
    if out.exists() and any(out.iterdir()):
        raise CaptureError(f"capture output directory is not empty: {out}")
    out.mkdir(parents=True, exist_ok=True)
    out.chmod(0o777)
    env = os.environ.copy()
    env["VARIANT"] = variant
    env["OUT_DIR"] = str(out)
    env.pop("COMPOSE_PROFILES", None)
    if variant == "negative":
        env["COMPOSE_PROFILES"] = "multi"
    project = f"egressdiff-f11-{os.getpid()}-{variant}-{uuid.uuid4().hex[:8]}"
    image_ids: set[str] = set()
    report: dict[str, object] | None = None
    primary: BaseException | None = None
    try:
        result = run(
            [
                "docker",
                "compose",
                "-p",
                project,
                "up",
                "--build",
                "--abort-on-container-exit",
                "--exit-code-from",
                "capture",
            ],
            cwd=fixture,
            env=env,
            timeout=180,
            check=False,
        )
        ps = run(
            ["docker", "compose", "-p", project, "ps", "--all", "-q"],
            cwd=fixture,
            env=env,
            check=False,
        )
        if ps.returncode != 0:
            up_detail = (result.stdout + result.stderr)[-2500:]
            ps_detail = (ps.stderr or ps.stdout).strip()
            raise CaptureError(f"compose ps: {ps_detail}; compose up: {up_detail}")
        container_ids = ps.stdout.split()
        if not container_ids:
            raise CaptureError("no containers found after capture")
        inspected = json.loads(
            run(["docker", "inspect", *container_ids], cwd=fixture, env=env).stdout
        )
        image_ids = {item["Image"] for item in inspected}
        captures = [
            item
            for item in inspected
            if item["Config"]["Labels"].get("com.docker.compose.service") == "capture"
        ]
        if len(captures) != 1:
            raise CaptureError(f"expected exactly one capture container, got {len(captures)}")
        report_path = out / "capture.json"
        if not report_path.is_file():
            raise CaptureError(f"capture.json not found; compose rc={result.returncode}")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["compose_rc"] = result.returncode
        report["runtime"] = runtime_security(captures[0])
        services = {
            item["Config"]["Labels"].get("com.docker.compose.service") for item in inspected
        }
        unexpected_services = services - SUPPORTED_FIXTURE_SERVICES
        if unexpected_services:
            report["unknown"] = sorted(
                set(report["unknown"])
                | {f"multi_service_unsupported:{name}" for name in unexpected_services}
            )
        report["service"] = "app"
        validate_report(report)
        write_json_atomic(report_path, report)
    except BaseException as exc:
        primary = exc
    try:
        cleanup(project, fixture, env, image_ids)
    except Exception as cleanup_error:
        if primary:
            raise CaptureError(
                f"{primary}; additional cleanup failure: {cleanup_error}"
            ) from cleanup_error
        raise
    if primary:
        raise primary
    if report is None:
        raise CaptureError("capture result is missing")
    return report
