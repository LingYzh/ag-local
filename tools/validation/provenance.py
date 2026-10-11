"""Repository-scoped provenance; no environment variable values or user paths."""
from __future__ import annotations

import hashlib
import importlib.metadata
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE_DIRS = ("desktop/src", "desktop/scripts", "desktop/tests", "v5_server/bootstrap",
               "v5_server/network", "v5_server/tools", "tools", "tests")
SOURCE_SUFFIXES = {".py", ".ts", ".vue", ".mjs", ".json", ".ps1", ".in", ".lock", ".yml"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_hashes() -> dict[str, str]:
    files: set[Path] = set()
    for relative in SOURCE_DIRS:
        directory = ROOT / relative
        if directory.exists():
            files.update(path for path in directory.rglob("*")
                         if path.is_file() and path.suffix in SOURCE_SUFFIXES
                         and "__pycache__" not in path.parts)
    files.update((ROOT / "desktop").glob("*.json"))
    files.update((ROOT / "desktop").glob("*.ts"))
    files.update((ROOT / ".github/workflows").glob("*.yml"))
    files.update(path for path in (ROOT / "LICENSE", ROOT / ".gitattributes", ROOT / "desktop/THIRD_PARTY_NOTICES.txt")
                 if path.is_file())
    return {path.relative_to(ROOT).as_posix(): sha256(path) for path in sorted(files)}


def git_value(*args: str) -> str | None:
    try:
        result = subprocess.run(["git", "-C", str(ROOT), *args], check=True,
                                capture_output=True, text=True, encoding="utf-8")
        return result.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def provenance(hashes: dict[str, str] | None = None) -> dict:
    status = git_value("status", "--porcelain", "--untracked-files=normal")
    lock = ROOT / "tools/python/requirements-win-cp314-x64.lock"
    distribution_zip = Path(sys.base_prefix).parent / "python-3.14.6-amd64.zip"
    package_versions: dict[str, str | None] = {}
    for name in ("pip", "UnityPy", "lz4"):
        try:
            package_versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            package_versions[name] = None
    return {
        "format_version": 1,
        "baseline_commit": git_value("rev-parse", "HEAD"),
        "workspace_dirty": None if status is None else bool(status),
        "source_sha256": source_hashes() if hashes is None else hashes,
        "environment": {
            "os": platform.system(), "os_release": platform.release(),
            "architecture": platform.machine(), "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "isolated": bool(sys.flags.isolated),
            "interpreter_sha256": sha256(Path(sys.executable)),
            "runtime_distribution_sha256": sha256(distribution_zip) if distribution_zip.is_file() else None,
            "dependency_lock_sha256": sha256(lock) if lock.is_file() else None,
            "installed_key_package_versions": package_versions,
        },
        "privacy": "Repository-relative source paths and allowlisted metadata only; no credentials, payloads or environment values.",
    }
