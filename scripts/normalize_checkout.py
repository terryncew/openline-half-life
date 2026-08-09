from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

IGNORED_TOP_LEVEL = {".git", ".pytest_cache", ".venv", "build", "dist", "release-work"}
IGNORED_SUFFIXES = {".pyc", ".pyo"}


def normalize(root: Path, manifest_path: Path) -> dict:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = {entry["path"] for entry in manifest["entries"]} | {manifest_path.relative_to(root).as_posix()}
    removed: list[str] = []
    for path in sorted(root.rglob("*"), key=lambda value: len(value.parts), reverse=True):
        rel = path.relative_to(root)
        if rel.parts and rel.parts[0] in IGNORED_TOP_LEVEL:
            continue
        if path.is_file() or path.is_symlink():
            rel_posix = rel.as_posix()
            if rel_posix not in expected and path.suffix not in IGNORED_SUFFIXES:
                path.unlink()
                removed.append(rel_posix)
        elif path.is_dir() and not any(path.iterdir()):
            path.rmdir()
    return {"removed_count": len(removed), "removed": sorted(removed)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--manifest", type=Path, default=Path("RELEASE_MANIFEST.json"))
    args = parser.parse_args()
    root = args.root.resolve()
    manifest = args.manifest if args.manifest.is_absolute() else root / args.manifest
    result = normalize(root, manifest)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
