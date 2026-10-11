from __future__ import annotations

import ast
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import site
import struct
import subprocess
import sys
import sysconfig
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DIRECT_INPUT = ROOT / "tools" / "python" / "requirements.in"
LOCK_FILE = ROOT / "tools" / "python" / "requirements-win-cp314-x64.lock"
STATIC_RECOVERY = ROOT / "v5_server" / "tools" / "static_protocol"
STATIC_EXTRACT_WRAPPER = ROOT / "tools" / "python" / "run-static-extract.py"
STD_LIBRARY_BOUNDARIES = (
    ROOT / "v5_server" / "bootstrap",
    ROOT / "v5_server" / "network",
    ROOT / "tools" / "evidence",
    ROOT / "tools" / "validation",
)
EXPECTED_LOCK_SHA256 = "d38f3b944957676e00b57a817aded2d9009b88c93ef6f9b4998b60b0bc3919cb"
EXPECTED_RUNTIME_ZIP_SHA256 = "75afa83f93b284d19040e24bc440ab741c09582c0d5310504d607a4e08c3dbaf"
EXPECTED_PIP_VERSION = "26.1.2"
EXPECTED_PIP_WHEEL = "pip-26.1.2-py3-none-any.whl"
EXPECTED_PIP_WHEEL_SHA256 = "382ff9f685ee3bc25864f820aa50505825f10f5458ffff07e30a6d96e5715cab"
EXPECTED_LOCKED_PACKAGES = {
    "archspec",
    "astc-encoder-py",
    "attrs",
    "brotli",
    "etcpak",
    "fmod-toolkit",
    "fsspec",
    "lz4",
    "pillow",
    "pyfmodex",
    "texture2ddecoder",
    "unitypy",
}


def _canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _python_files(directory: Path) -> list[Path]:
    return sorted(path for path in directory.rglob("*.py") if path.is_file())


def _is_stdlib_or_repository_import(module_name: str, source_path: Path) -> bool:
    root_name = module_name.split(".", 1)[0]
    if root_name == "__future__" or root_name in sys.stdlib_module_names:
        return True
    candidates = (ROOT / root_name, source_path.parent / root_name)
    return any(candidate.is_dir() or candidate.with_suffix(".py").is_file()
               for candidate in candidates)


def _third_party_imports(files: list[Path]) -> set[str]:
    external: set[str] = set()
    for source_path in files:
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported = [node.module]
            else:
                continue
            for module_name in imported:
                if not _is_stdlib_or_repository_import(module_name, source_path):
                    external.add(module_name.split(".", 1)[0])
    return external


class PythonEnvironmentContractTests(unittest.TestCase):
    def test_current_venv_matches_the_locked_runtime_and_imports(self) -> None:
        self.assertEqual(sys.version_info[:3], (3, 14, 6))
        self.assertEqual(platform.python_implementation(), "CPython")
        self.assertEqual(sys.platform, "win32")
        self.assertEqual(sysconfig.get_platform(), "win-amd64")
        self.assertEqual(platform.machine().upper(), "AMD64")
        self.assertEqual(struct.calcsize("P") * 8, 64)
        self.assertEqual(sysconfig.get_config_var("Py_GIL_DISABLED"), 0)
        self.assertNotEqual(sys.prefix, sys.base_prefix)
        self.assertEqual(sys.flags.isolated, 1)
        self.assertFalse(site.ENABLE_USER_SITE)

        runtime_zip = Path(sys.base_prefix).parent / "python-3.14.6-amd64.zip"
        self.assertTrue(runtime_zip.is_file(), "verified official runtime ZIP is missing")
        self.assertEqual(_sha256_file(runtime_zip), EXPECTED_RUNTIME_ZIP_SHA256)

        bundled_pip = (
            Path(sys.base_prefix)
            / "Lib"
            / "ensurepip"
            / "_bundled"
            / EXPECTED_PIP_WHEEL
        )
        self.assertTrue(bundled_pip.is_file(), "bundled pip wheel is missing")
        self.assertEqual(_sha256_file(bundled_pip), EXPECTED_PIP_WHEEL_SHA256)
        self.assertEqual(importlib.metadata.version("pip"), EXPECTED_PIP_VERSION)

        import UnityPy
        import lz4.block

        self.assertEqual(importlib.metadata.version("UnityPy"), "1.25.2")
        self.assertEqual(importlib.metadata.version("lz4"), "4.4.5")
        self.assertTrue(Path(UnityPy.__file__).is_file())
        self.assertTrue(Path(lz4.block.__file__).is_file())

    def test_direct_input_is_limited_to_the_static_extractor_imports(self) -> None:
        lines = [
            line.strip()
            for line in DIRECT_INPUT.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(lines, ["UnityPy==1.25.2", "lz4==4.4.5"])

    def test_every_locked_distribution_is_exactly_pinned_and_hashed(self) -> None:
        self.assertEqual(_sha256_file(LOCK_FILE), EXPECTED_LOCK_SHA256)
        entry_pattern = re.compile(
            r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)=="
            r"(?P<version>[A-Za-z0-9][A-Za-z0-9.+_-]*) "
            r"--hash=sha256:(?P<sha256>[a-f0-9]{64})$"
        )
        entries: dict[str, tuple[str, str]] = {}
        for raw_line in LOCK_FILE.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            match = entry_pattern.fullmatch(line)
            self.assertIsNotNone(match, f"lock entry lacks an exact pin or SHA-256: {line}")
            assert match is not None
            name = _canonical_name(match.group("name"))
            self.assertNotIn(name, entries, f"duplicate locked distribution: {name}")
            entries[name] = (match.group("version"), match.group("sha256"))

        self.assertEqual(set(entries), EXPECTED_LOCKED_PACKAGES)
        self.assertEqual(entries["unitypy"][0], "1.25.2")
        self.assertEqual(entries["lz4"][0], "4.4.5")

    def test_control_framing_evidence_and_validation_imports_are_stdlib_only(self) -> None:
        files = [path for directory in STD_LIBRARY_BOUNDARIES for path in _python_files(directory)]
        self.assertTrue(files, "expected source boundaries are missing")
        self.assertEqual(_third_party_imports(files), set())

    def test_static_recovery_uses_only_its_two_declared_external_packages(self) -> None:
        self.assertEqual(_third_party_imports(_python_files(STATIC_RECOVERY)), {"UnityPy", "lz4"})

    def test_static_extractor_wrapper_requires_isolated_mode(self) -> None:
        clean_env = os.environ.copy()
        for name in ("PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE"):
            clean_env.pop(name, None)

        unisolated = subprocess.run(
            [sys.executable, "-S", "-B", str(STATIC_EXTRACT_WRAPPER)],
            check=False,
            capture_output=True,
            encoding="utf-8",
            env=clean_env,
        )
        self.assertNotEqual(unisolated.returncode, 0)
        self.assertIn("Run this wrapper with Python -I.", unisolated.stderr)

        isolated_help = subprocess.run(
            [sys.executable, "-I", "-B", str(STATIC_EXTRACT_WRAPPER), "--help"],
            check=False,
            capture_output=True,
            encoding="utf-8",
            env=clean_env,
        )
        self.assertEqual(isolated_help.returncode, 0, isolated_help.stderr)
        self.assertIn("--source-root", isolated_help.stdout)

    def test_isolated_python_ignores_pythonpath_user_site_and_pythonhome(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ag-h02-isolation-") as temp_name:
            temp_root = Path(temp_name)
            python_path = temp_root / "python-path"
            user_base = temp_root / "user-base"
            marker = temp_root / "sitecustomize-imported.txt"
            python_path.mkdir()
            (python_path / "h02_pythonpath_probe.py").write_text(
                "VALUE = 'must not be imported'\n", encoding="utf-8"
            )
            (python_path / "sitecustomize.py").write_text(
                "import os\nfrom pathlib import Path\n"
                "Path(os.environ['AG_H02_MARKER']).write_text('imported', encoding='ascii')\n",
                encoding="utf-8",
            )

            user_site_env = os.environ.copy()
            user_site_env.pop("PYTHONPATH", None)
            user_site_env.pop("PYTHONHOME", None)
            user_site_env["PYTHONUSERBASE"] = str(user_base)
            user_site_result = subprocess.run(
                [
                    sys.executable,
                    "-s",
                    "-B",
                    "-c",
                    "import site; print(site.getusersitepackages())",
                ],
                check=True,
                capture_output=True,
                encoding="utf-8",
                env=user_site_env,
            )
            user_site = Path(user_site_result.stdout.strip()).resolve()
            self.assertTrue(user_site.is_relative_to(user_base.resolve()))
            user_site.mkdir(parents=True, exist_ok=True)
            (user_site / "h02_user_site_probe.py").write_text(
                "VALUE = 'must not be imported'\n", encoding="utf-8"
            )

            isolated_env = os.environ.copy()
            isolated_env["PYTHONPATH"] = str(python_path)
            isolated_env["PYTHONUSERBASE"] = str(user_base)
            isolated_env["PYTHONHOME"] = str(temp_root)
            isolated_env["AG_H02_MARKER"] = str(marker)
            probe_code = (
                "import importlib.util, json, site, sys; "
                "print(json.dumps({"
                "'isolated': sys.flags.isolated, "
                "'ignore_environment': sys.flags.ignore_environment, "
                "'no_user_site': sys.flags.no_user_site, "
                "'user_site_enabled': site.ENABLE_USER_SITE, "
                "'pythonpath_module': importlib.util.find_spec('h02_pythonpath_probe') is not None, "
                "'user_site_module': importlib.util.find_spec('h02_user_site_probe') is not None"
                "}))"
            )
            result = subprocess.run(
                [sys.executable, "-I", "-B", "-c", probe_code],
                check=True,
                capture_output=True,
                encoding="utf-8",
                env=isolated_env,
            )
            observed = json.loads(result.stdout)

            self.assertEqual(observed["isolated"], 1)
            self.assertEqual(observed["ignore_environment"], 1)
            self.assertEqual(observed["no_user_site"], 1)
            self.assertFalse(observed["user_site_enabled"])
            self.assertFalse(observed["pythonpath_module"])
            self.assertFalse(observed["user_site_module"])
            self.assertFalse(marker.exists(), "sitecustomize ran despite isolated mode")


if __name__ == "__main__":
    unittest.main()
