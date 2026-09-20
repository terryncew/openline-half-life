from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from importlib.metadata import PackageNotFoundError, version as package_version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def is_generated_release_path(rel: Path) -> bool:
    """Return True for tool-generated files that are not release source."""
    if rel.parts and rel.parts[0] in {".git", ".pytest_cache", ".venv", "build", "dist", "release-work"}:
        return True
    if any(part.endswith(".egg-info") for part in rel.parts):
        return True
    if "__pycache__" in rel.parts or rel.suffix in {".pyc", ".pyo"}:
        return True
    return False


def run(command: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(command, cwd=cwd or ROOT, env=merged, capture_output=True, text=True)


def manifest_check() -> dict:
    manifest = json.loads((ROOT / "RELEASE_MANIFEST.json").read_text(encoding="utf-8"))
    entries = {item["path"]: item for item in manifest["entries"]}
    expected = set(entries) | {"RELEASE_MANIFEST.json"}
    actual = set()
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel_path = path.relative_to(ROOT)
        if is_generated_release_path(rel_path):
            continue
        actual.add(rel_path.as_posix())
    errors = []
    if actual != expected:
        errors.append({"closure_mismatch": {"missing": sorted(expected - actual), "extra": sorted(actual - expected)}})
    import hashlib
    for rel, item in entries.items():
        path = ROOT / rel
        if not path.is_file():
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != item["sha256"] or path.stat().st_size != item["bytes"]:
            errors.append({"hash_mismatch": rel})
    return {"passed": not errors, "file_count": len(expected), "errors": errors}


def main() -> int:
    checks: dict[str, object] = {"schema": "openline.half-life.release-check.v1", "version": "0.4.0rc3"}
    closure = manifest_check()
    checks["manifest"] = closure
    if not closure["passed"]:
        print(json.dumps(checks, indent=2, sort_keys=True))
        return 1

    pytest = run([sys.executable, "-m", "pytest", "-q"], env={"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"})
    checks["tests"] = {"passed": pytest.returncode == 0, "returncode": pytest.returncode, "summary": (pytest.stdout + pytest.stderr)[-1200:]}

    hostile = run([sys.executable, str(ROOT / "scripts/hostile_checks.py")], env={"PYTHONPATH": f"{ROOT / 'src'}:{ROOT}"})
    hostile_json = None
    try:
        hostile_json = json.loads(hostile.stdout)
    except Exception:
        pass
    checks["hostile_checks"] = hostile_json if isinstance(hostile_json, dict) else {"passed": False, "returncode": hostile.returncode, "stderr": hostile.stderr[-1000:]}

    with tempfile.TemporaryDirectory(prefix="half-life-release-") as tmp:
        tmp = Path(tmp)
        demo = run([sys.executable, "-m", "openline_half_life", "demo", "--out", str(tmp / "demo"), "--json"])
        demo_json = None
        try:
            demo_json = json.loads(demo.stdout)
        except Exception:
            pass
        checks["demo"] = {"passed": demo.returncode == 0 and isinstance(demo_json, dict) and demo_json.get("passed") is True, "returncode": demo.returncode}

        verify = run([sys.executable, "-m", "openline_half_life", "verify", str(tmp / "demo"), "--compaction-policy-public-key", str(ROOT / "policy/compaction_policy_public_key.hex")])
        verify_json = None
        try:
            verify_json = json.loads(verify.stdout)
        except Exception:
            pass
        checks["output_verification"] = {"passed": verify.returncode == 0 and isinstance(verify_json, dict) and verify_json.get("valid") is True, "returncode": verify.returncode}

        seeded = run([sys.executable, str(ROOT / "scripts/seeded_gate.py"), "--count", "10000"], env={"PYTHONPATH": f"{ROOT / 'src'}:{ROOT}"})
        seeded_json = None
        try:
            seeded_json = json.loads(seeded.stdout)
        except Exception:
            pass
        checks["seeded_gate"] = seeded_json if isinstance(seeded_json, dict) else {"passed": False, "returncode": seeded.returncode, "stderr": seeded.stderr[-1000:]}

        src_copy = tmp / "source"
        shutil.copytree(ROOT, src_copy, ignore=shutil.ignore_patterns(".git", ".pytest_cache", ".venv", "build", "dist", "release-work", "__pycache__", "*.pyc", "*.pyo", "*.egg-info"))
        wheel_dir = tmp / "wheel"
        wheel_dir.mkdir()
        try:
            setuptools_version = package_version("setuptools")
        except PackageNotFoundError:
            setuptools_version = "0"
        build_cmd = [sys.executable, "-m", "pip", "wheel", ".", "--no-deps", "-w", str(wheel_dir)]
        # CI installs the declared dev requirements first. When a compatible
        # backend is already present, avoid an unnecessary index lookup.
        try:
            major = int(setuptools_version.split(".", 1)[0])
        except ValueError:
            major = 0
        if major >= 68:
            build_cmd.insert(-2, "--no-build-isolation")
        wheel = run(build_cmd, cwd=src_copy)
        wheels = list(wheel_dir.glob("*.whl"))
        site = tmp / "site"
        site.mkdir()
        install = run([sys.executable, "-m", "pip", "install", "--no-deps", "--target", str(site), str(wheels[0])]) if len(wheels) == 1 else None
        imported = run([sys.executable, "-c", "import openline_half_life; print(openline_half_life.__version__)"], cwd=tmp, env={"PYTHONPATH": str(site)}) if install and install.returncode == 0 else None
        installed_demo = run([sys.executable, "-m", "openline_half_life", "demo", "--out", str(tmp / "installed-demo"), "--json"], cwd=tmp, env={"PYTHONPATH": str(site)}) if imported and imported.returncode == 0 else None
        checks["wheel"] = {
            "passed": wheel.returncode == 0 and len(wheels) == 1 and install is not None and install.returncode == 0 and imported is not None and imported.returncode == 0 and imported.stdout.strip() == "0.4.0rc3" and installed_demo is not None and installed_demo.returncode == 0,
            "build_returncode": wheel.returncode,
            "wheel_count": len(wheels),
            "setuptools_version": setuptools_version,
            "imported_version": imported.stdout.strip() if imported else "",
        }

    checks["passed"] = all(
        value.get("passed") is True
        for key, value in checks.items()
        if key not in {"schema", "version", "passed"} and isinstance(value, dict)
    )
    print(json.dumps(checks, indent=2, sort_keys=True))
    return 0 if checks["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
