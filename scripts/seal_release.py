from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_TOP = {".git", ".pytest_cache", ".venv", "build", "dist", "release-work"}


def main() -> int:
    entries = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if rel.as_posix() == "RELEASE_MANIFEST.json":
            continue
        if rel.parts and rel.parts[0] in EXCLUDED_TOP:
            continue
        if any(part.endswith(".egg-info") for part in rel.parts):
            continue
        if "__pycache__" in rel.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        data = path.read_bytes()
        entries.append({"path": rel.as_posix(), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    manifest = {"schema": "openline.half-life.release-manifest.v1", "version": "0.4.0rc3", "entries": entries}
    (ROOT / "RELEASE_MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"entry_count": len(entries), "manifest_sha256": hashlib.sha256((ROOT / "RELEASE_MANIFEST.json").read_bytes()).hexdigest()}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
