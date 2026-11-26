from __future__ import annotations

import json
import os
import socket
import ssl
import time
import urllib.request
from pathlib import Path

OUT = Path("/out")


def wait_for_capture() -> None:
    for _ in range(300):
        if (OUT / "capture.ready").exists():
            return
        if (OUT / "capture.failed").exists():
            raise RuntimeError("capture failed")
        time.sleep(0.1)
    raise RuntimeError("capture readiness timeout")


def wait_for_capture_done() -> bool:
    for _ in range(150):
        if (OUT / "capture.done").exists():
            return True
        time.sleep(0.1)
    return False


def main() -> int:
    variant = os.environ["VARIANT"]
    result: dict[str, object] = {"variant": variant, "rc": 1, "status": "FAIL"}
    try:
        wait_for_capture()
        if not os.environ.get("SECRET_CANARY"):
            raise RuntimeError("missing secret canary")
        if variant == "failure":
            raise RuntimeError("synthetic failure")
        if variant == "sigint":
            time.sleep(60)
            raise RuntimeError("sigint fixture was not interrupted")
        if variant == "negative":
            with urllib.request.urlopen("http://172.31.0.10:8000/", timeout=5) as response:
                if response.read() != b"db\n":
                    raise RuntimeError("bad direct-IP response")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(b"quic-shaped", ("172.31.0.20", 443))
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
                sock.sendto(b"ipv6", ("::1", 443))
        else:
            with urllib.request.urlopen("http://db.example:8000/", timeout=5) as response:
                if response.read() != b"db\n":
                    raise RuntimeError("bad db response")
            if variant == "candidate":
                context = ssl._create_unverified_context()  # noqa: SLF001 — synthetic fixture only
                with urllib.request.urlopen(
                    "https://telemetry.example:9443/", timeout=5, context=context
                ) as response:
                    if response.read() != b"telemetry\n":
                        raise RuntimeError("bad telemetry response")
        result.update(rc=0, status="PASS")
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    (OUT / "smoke.json").write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
    (OUT / "smoke.done").write_text("done\n", encoding="ascii")
    if not wait_for_capture_done():
        result.update(rc=1, status="FAIL", error="capture completion timeout")
        (OUT / "smoke.json").write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
    return int(result["rc"])


if __name__ == "__main__":
    raise SystemExit(main())
