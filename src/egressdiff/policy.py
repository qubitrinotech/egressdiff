from __future__ import annotations

import json
from pathlib import Path

from .runner import write_json_atomic

POLICY_SCHEMA_VERSION = 1


def load_policy(path: Path) -> list[str]:
    if not path.exists():
        return []
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("policy must be a JSON object")
    if set(value) != {"schema_version", "approved_keys"}:
        raise ValueError("policy keys must be exactly schema_version/approved_keys")
    if value["schema_version"] != POLICY_SCHEMA_VERSION:
        raise ValueError("policy schema_version != 1")
    keys = value["approved_keys"]
    if not isinstance(keys, list) or any(
        not isinstance(key, str) or not key or key.strip() != key for key in keys
    ):
        raise ValueError("approved_keys must be a list of non-empty strings")
    if len(keys) != len(set(keys)):
        raise ValueError("approved_keys contains duplicates")
    return sorted(keys)


def apply_policy(diff: dict[str, object], approved_keys: list[str]) -> dict[str, object]:
    result = dict(diff)
    new_keys = {item["key"] for item in result["new"]}
    approved = set(approved_keys)
    result["approved_keys"] = sorted(new_keys & approved)
    result["unapproved_keys"] = sorted(new_keys - approved)
    if any(result["unknown"].values()):
        result["verdict"] = "UNKNOWN"
    elif result["unapproved_keys"]:
        result["verdict"] = "REVIEW_REQUIRED"
    else:
        result["verdict"] = "PASS"
    return result


def approve_key(diff: dict[str, object], policy_path: Path, key: str) -> list[str]:
    new_keys = {item["key"] for item in diff["new"]}
    if key not in new_keys:
        raise ValueError("key is not in NEW")
    keys = load_policy(policy_path)
    if key not in keys:
        keys = sorted([*keys, key])
        write_json_atomic(
            policy_path,
            {"schema_version": POLICY_SCHEMA_VERSION, "approved_keys": keys},
        )
    return keys
