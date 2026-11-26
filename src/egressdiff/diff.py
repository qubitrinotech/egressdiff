from __future__ import annotations

import json
from pathlib import Path

from .normalize import normalize


def make_diff(baseline: dict[str, object], candidate: dict[str, object]) -> dict[str, object]:
    before = {item["key"]: item for item in normalize(baseline)}
    after = {item["key"]: item for item in normalize(candidate)}
    unknown = {
        "baseline": sorted(baseline["unknown"]),
        "candidate": sorted(candidate["unknown"]),
    }
    new = [after[key] for key in sorted(after.keys() - before.keys())]
    removed = [before[key] for key in sorted(before.keys() - after.keys())]
    verdict = "UNKNOWN" if any(unknown.values()) else "REVIEW_REQUIRED" if new else "PASS"
    return {
        "schema_version": 1,
        "new": new,
        "removed": removed,
        "unknown": unknown,
        "verdict": verdict,
    }


def markdown(diff: dict[str, object]) -> str:
    lines = ["# EgressDiff diff", "", f"Verdict: **{diff['verdict']}**", ""]
    lines.append("## New destinations")
    lines.append("")
    if diff["new"]:
        approved = set(diff.get("approved_keys", []))
        for item in diff["new"]:
            label = item.get("name") or item.get("address")
            evidence = ",".join(item["evidence"])
            status = "NEW APPROVED" if item["key"] in approved else "NEW"
            lines.append(f"- **{status}** `{item['service']}` → `{label}`; evidence: {evidence}")
    else:
        lines.append("None")
    lines.extend(["", "## Removed destinations", ""])
    if diff["removed"]:
        for item in diff["removed"]:
            label = item.get("name") or item.get("address")
            lines.append(f"- **REMOVED** `{item['service']}` → `{label}`")
    else:
        lines.append("None")
    lines.extend(
        ["", "## Unknown", "", f"```json\n{json.dumps(diff['unknown'], sort_keys=True)}\n```", ""]
    )
    return "\n".join(lines)


def write_diff(diff: dict[str, object], out: Path) -> tuple[Path, Path]:
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        raise ValueError(f"diff output directory is not empty: {out}")
    json_path = out / "diff.json"
    markdown_path = out / "diff.md"
    json_path.write_text(json.dumps(diff, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(markdown(diff), encoding="utf-8")
    return json_path, markdown_path
