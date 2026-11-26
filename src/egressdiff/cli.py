from __future__ import annotations

import argparse
import json
from pathlib import Path

from .diff import make_diff, write_diff
from .policy import apply_policy, approve_key, load_policy
from .runner import CaptureError, capture_fixture


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="egressdiff")
    sub = result.add_subparsers(dest="command", required=True)
    capture = sub.add_parser("capture", help="run the synthetic capture fixture")
    capture.add_argument("--fixture-dir", type=Path, required=True)
    capture.add_argument(
        "--variant",
        choices=("baseline", "candidate", "negative", "failure", "sigint"),
        required=True,
    )
    capture.add_argument("--out", type=Path, required=True)
    diff = sub.add_parser("diff", help="compare two capture.json files")
    diff.add_argument("--baseline", type=Path, required=True)
    diff.add_argument("--candidate", type=Path, required=True)
    diff.add_argument("--out", type=Path, required=True)
    check = sub.add_parser("check", help="apply a policy to diff.json")
    check.add_argument("--diff", dest="diff_path", type=Path, required=True)
    check.add_argument("--policy", type=Path, required=True)
    check.add_argument("--out", type=Path, required=True)
    approve = sub.add_parser("approve", help="approve one NEW destination")
    approve.add_argument("--diff", dest="diff_path", type=Path, required=True)
    approve.add_argument("--key", required=True)
    approve.add_argument("--policy", type=Path, required=True)
    return result


def write_and_print(diff: dict[str, object], out: Path) -> None:
    json_path, markdown_path = write_diff(diff, out)
    print(f"DIFF_JSON={json_path}")
    print(f"DIFF_MARKDOWN={markdown_path}")
    print(f"VERDICT={diff['verdict']}")


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "capture":
            report = capture_fixture(args.fixture_dir, args.variant, args.out)
            print(f"CAPTURE={args.out.resolve() / 'capture.json'}")
            print(f"SMOKE={report['smoke']['status']}")
            print(f"UNKNOWN={len(report['unknown'])}")
            return 0
        if args.command == "approve":
            diff = json.loads(args.diff_path.read_text(encoding="utf-8"))
            keys = approve_key(diff, args.policy, args.key)
            print(f"POLICY={args.policy}")
            print(f"APPROVED={args.key}")
            print(f"APPROVED_KEYS={len(keys)}")
            return 0
        if args.command == "check":
            raw = json.loads(args.diff_path.read_text(encoding="utf-8"))
            diff = apply_policy(raw, load_policy(args.policy))
            write_and_print(diff, args.out)
            print(f"APPROVED_NEW={len(diff['approved_keys'])}")
            print(f"UNAPPROVED_NEW={len(diff['unapproved_keys'])}")
            return {"PASS": 0, "REVIEW_REQUIRED": 1, "UNKNOWN": 2}[diff["verdict"]]
        baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
        candidate = json.loads(args.candidate.read_text(encoding="utf-8"))
        write_and_print(make_diff(baseline, candidate), args.out)
        return 0
    except (CaptureError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"STOP: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
