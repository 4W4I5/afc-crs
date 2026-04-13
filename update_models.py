#!/usr/bin/env python3
"""Project-wide model ID updater.

This script reads the authoritative model catalog from models.json, validates
replacement targets, and updates model IDs in source/test files.

Default behavior is dry-run. Use --apply to write changes.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Set, Tuple

# Explicit default mapping table (old_id -> new_id).
# Update this table as new model migrations are needed.
DEFAULT_MODEL_REPLACEMENTS: Dict[str, str] = {
    "claude-sonnet-4": "claude-sonnet-4.6",
    "claude-sonnet-4.5": "claude-sonnet-4.6",
    "claude-opus-4.5": "claude-opus-4.6",
    "gemini-2.5-pro": "gemini-3.1-pro-preview",
    "gpt-5.1": "gpt-5.4",
    "gpt-5.2": "gpt-5.4",
}

DEFAULT_EXTENSIONS: Set[str] = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".jsx",
    ".py",
    ".rs",
    ".ts",
    ".tsx",
}

EXCLUDED_DIRS: Set[str] = {
    ".git",
    ".hg",
    ".idea",
    ".mypy_cache",
    ".pytest_cache",
    ".svn",
    ".terraform",
    ".venv",
    "__pycache__",
    "bin",
    "build",
    "dist",
    "node_modules",
    "patch",
    "pov",
    "workspace",
    "WORKFLOW",
}

TOKEN_CHARS = r"A-Za-z0-9._/-"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Update model IDs in source/test files using an explicit replacement mapping."
        )
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="Repository root to scan (default: script directory).",
    )
    parser.add_argument(
        "--models-file",
        type=Path,
        default=Path("models.json"),
        help="Path to authoritative models JSON (default: models.json).",
    )
    parser.add_argument(
        "--mapping-file",
        type=Path,
        help="Optional JSON file with old_id->new_id mapping entries.",
    )
    parser.add_argument(
        "--map",
        action="append",
        default=[],
        metavar="OLD=NEW",
        help="Inline mapping override. Can be provided multiple times.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write changes to disk. Default is dry-run (no writes).",
    )
    parser.add_argument(
        "--include-tests",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Include test files (default: true).",
    )
    parser.add_argument(
        "--path",
        action="append",
        default=[],
        metavar="REL_PATH",
        help="Optional relative path(s) to limit scanning scope.",
    )
    parser.add_argument(
        "--ext",
        action="append",
        default=[],
        metavar="EXT",
        help="Additional file extension to scan, e.g. --ext .swift",
    )
    parser.add_argument(
        "--fail-on-missing",
        action="store_true",
        help="Fail if any mapped old model ID was not found in scanned files.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print per-file replacement details.",
    )
    return parser.parse_args()


def load_models(models_path: Path) -> Set[str]:
    try:
        payload = json.loads(models_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"models file not found: {models_path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in models file: {models_path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise ValueError("models file must contain a top-level JSON object")

    data = payload.get("data")
    if not isinstance(data, list):
        raise ValueError('models file must contain a list at key "data"')

    model_ids: Set[str] = set()
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"models.data[{index}] must be an object")
        model_id = item.get("id")
        if not isinstance(model_id, str) or not model_id.strip():
            raise ValueError(f"models.data[{index}].id must be a non-empty string")
        model_ids.add(model_id)

    if not model_ids:
        raise ValueError("models file contains no model IDs")
    return model_ids


def parse_mapping_entries(entries: Sequence[str]) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for raw in entries:
        if "=" not in raw:
            raise ValueError(f"invalid --map entry '{raw}', expected OLD=NEW")
        old, new = raw.split("=", 1)
        old = old.strip()
        new = new.strip()
        if not old or not new:
            raise ValueError(f"invalid --map entry '{raw}', OLD and NEW must be non-empty")
        parsed[old] = new
    return parsed


def load_mapping(args: argparse.Namespace, model_ids: Set[str]) -> Dict[str, str]:
    mapping: Dict[str, str] = dict(DEFAULT_MODEL_REPLACEMENTS)

    if args.mapping_file:
        try:
            file_payload = json.loads(args.mapping_file.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ValueError(f"mapping file not found: {args.mapping_file}") from exc
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"invalid JSON in mapping file: {args.mapping_file}: {exc}"
            ) from exc

        if not isinstance(file_payload, dict):
            raise ValueError("mapping file must be a JSON object of old_id->new_id")
        for old, new in file_payload.items():
            if not isinstance(old, str) or not isinstance(new, str):
                raise ValueError("mapping keys and values must be strings")
            mapping[old] = new

    mapping.update(parse_mapping_entries(args.map))

    if not mapping:
        raise ValueError("replacement mapping is empty")

    invalid_targets = sorted({new for new in mapping.values() if new not in model_ids})
    if invalid_targets:
        raise ValueError(
            "mapping contains target IDs not present in models.json: "
            + ", ".join(invalid_targets)
        )

    return mapping


def normalize_extensions(extra_extensions: Sequence[str]) -> Set[str]:
    exts = set(DEFAULT_EXTENSIONS)
    for ext in extra_extensions:
        cleaned = ext.strip()
        if not cleaned:
            continue
        if not cleaned.startswith("."):
            cleaned = "." + cleaned
        exts.add(cleaned.lower())
    return exts


def is_test_file(path: Path) -> bool:
    lowered_parts = {part.lower() for part in path.parts}
    if "test" in lowered_parts or "tests" in lowered_parts:
        return True
    stem = path.stem.lower()
    return stem.startswith("test_") or stem.endswith("_test")


def iter_target_files(
    root: Path,
    scope_paths: Sequence[str],
    include_extensions: Set[str],
    include_tests: bool,
) -> Iterable[Path]:
    roots: List[Path]
    if scope_paths:
        roots = [root / rel for rel in scope_paths]
    else:
        roots = [root]

    seen: Set[Path] = set()

    for scan_root in roots:
        if not scan_root.exists():
            raise ValueError(f"scope path does not exist: {scan_root}")

        if scan_root.is_file():
            candidate_files = [scan_root]
        else:
            candidate_files = []
            for dirpath, dirnames, filenames in os.walk(scan_root):
                dirnames[:] = [
                    name
                    for name in dirnames
                    if name not in EXCLUDED_DIRS and not name.startswith(".")
                ]
                current_dir = Path(dirpath)
                for filename in filenames:
                    candidate_files.append(current_dir / filename)

        for file_path in candidate_files:
            if file_path in seen:
                continue
            seen.add(file_path)

            if file_path.suffix.lower() not in include_extensions:
                continue
            if not include_tests and is_test_file(file_path):
                continue
            if file_path.name.startswith("."):
                continue

            yield file_path


def replace_in_content(content: str, mapping: Dict[str, str]) -> Tuple[str, Dict[Tuple[str, str], int]]:
    replacements: Dict[Tuple[str, str], int] = defaultdict(int)
    updated = content

    # Process longer keys first to avoid edge collisions when keys overlap.
    for old, new in sorted(mapping.items(), key=lambda item: len(item[0]), reverse=True):
        pattern = re.compile(rf"(?<![{TOKEN_CHARS}]){re.escape(old)}(?![{TOKEN_CHARS}])")
        updated, count = pattern.subn(new, updated)
        if count:
            replacements[(old, new)] += count

    return updated, replacements


def process_file(path: Path, mapping: Dict[str, str], apply_changes: bool) -> Dict[Tuple[str, str], int]:
    try:
        original = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return {}

    updated, replacement_counts = replace_in_content(original, mapping)
    if not replacement_counts:
        return {}

    if apply_changes and updated != original:
        path.write_text(updated, encoding="utf-8")

    return replacement_counts


def print_summary(
    changed_files: Dict[Path, Dict[Tuple[str, str], int]],
    aggregate_counts: Dict[Tuple[str, str], int],
    root: Path,
    apply_changes: bool,
    verbose: bool,
) -> None:
    mode = "APPLY" if apply_changes else "DRY-RUN"
    print(f"Mode: {mode}")
    print(f"Changed files: {len(changed_files)}")

    total_replacements = sum(aggregate_counts.values())
    print(f"Total replacements: {total_replacements}")

    if not changed_files:
        return

    print("\nFiles:")
    for file_path in sorted(changed_files):
        rel = file_path.relative_to(root)
        count = sum(changed_files[file_path].values())
        print(f"  - {rel}: {count}")

    print("\nReplacement counts:")
    for (old, new), count in sorted(
        aggregate_counts.items(), key=lambda item: (-item[1], item[0][0])
    ):
        print(f"  - {old} -> {new}: {count}")

    if verbose:
        print("\nPer-file details:")
        for file_path in sorted(changed_files):
            rel = file_path.relative_to(root)
            print(f"  - {rel}")
            for (old, new), count in sorted(changed_files[file_path].items()):
                print(f"      {old} -> {new}: {count}")

    if not apply_changes:
        print("\nDry-run only. Re-run with --apply to write changes.")


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    models_path = (root / args.models_file).resolve() if not args.models_file.is_absolute() else args.models_file

    try:
        model_ids = load_models(models_path)
        mapping = load_mapping(args, model_ids)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    include_extensions = normalize_extensions(args.ext)

    changed_files: Dict[Path, Dict[Tuple[str, str], int]] = {}
    aggregate_counts: Dict[Tuple[str, str], int] = defaultdict(int)

    old_id_hits: Dict[str, int] = defaultdict(int)

    try:
        files = iter_target_files(
            root=root,
            scope_paths=args.path,
            include_extensions=include_extensions,
            include_tests=args.include_tests,
        )
        for file_path in files:
            replacement_counts = process_file(
                path=file_path,
                mapping=mapping,
                apply_changes=args.apply,
            )
            if not replacement_counts:
                continue

            changed_files[file_path] = replacement_counts
            for (old, new), count in replacement_counts.items():
                aggregate_counts[(old, new)] += count
                old_id_hits[old] += count
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    print_summary(
        changed_files=changed_files,
        aggregate_counts=aggregate_counts,
        root=root,
        apply_changes=args.apply,
        verbose=args.verbose,
    )

    missing_old_ids = sorted(old for old in mapping if old_id_hits.get(old, 0) == 0)
    if missing_old_ids:
        print("\nMapped IDs not found in scanned files:")
        for old in missing_old_ids:
            print(f"  - {old}")

    if args.fail_on_missing and missing_old_ids:
        print("\nError: --fail-on-missing is set and some mapped old IDs were not found.", file=sys.stderr)
        return 3

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
