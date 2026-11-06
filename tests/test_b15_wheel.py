"""B15 acceptance tests: Wheel distribution contains entry point module.

Tests prove:
- Criterion 1: Wheel memuat modul entry point yang dirujuk metadata
  (apiKeyScan.py), packages core/ and scanners/, and the console_scripts
  entry point ``apikeyscan = apiKeyScan:main``.
- Criterion 2: Setelah izin operator untuk instalasi terisolasi, console
  entry point berhasil menjalankan help/list-checks lokal dari luar
  checkout.  The isolated venv uses ``--system-site-packages`` so existing
  dependencies are visible without network; the wheel is installed with
  ``--no-deps`` so no packages are downloaded.  The venv is discarded
  after the test (criterion 3: tidak dilakukan ke environment pengguna
  yang aktif).
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build wheel to an isolated temp dir; return path to the .whl file.

    Copies the source tree to a temp dir before building so that setuptools
    build artifacts (``build/``, ``*.egg-info/``) are not left in the repo
    root.  Uses ``--no-deps`` and ``--no-build-isolation`` so no network
    access is needed and no packages are installed into the active env.
    """
    src_copy = tmp_path_factory.mktemp("wheel_src")
    for item in PROJECT_ROOT.iterdir():
        if item.name in {
            ".git",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
            "build",
            "dist",
            "tests",
            "reports",
            ".codeartsdoer",
            "htmlcov",
        }:
            continue
        if item.is_dir():
            shutil.copytree(item, src_copy / item.name, dirs_exist_ok=True)
        else:
            shutil.copy2(item, src_copy / item.name)

    outdir = tmp_path_factory.mktemp("wheel_build")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "-w",
            str(outdir),
            str(src_copy),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        pytest.fail(f"Wheel build failed:\nstdout={result.stdout}\nstderr={result.stderr}")
    wheels = list(outdir.glob("*.whl"))
    assert len(wheels) == 1, f"Expected exactly one wheel, got: {wheels}"
    return wheels[0]


@pytest.fixture(scope="module")
def wheel_names(built_wheel: Path) -> list[str]:
    """Return sorted list of archive member names."""
    with zipfile.ZipFile(built_wheel) as zf:
        return zf.namelist()


@pytest.fixture(scope="module")
def wheel_dist_info(built_wheel: Path) -> dict[str, str]:
    """Return dict mapping dist-info file name → decoded text content."""
    info: dict[str, str] = {}
    with zipfile.ZipFile(built_wheel) as zf:
        for name in zf.namelist():
            if ".dist-info/" in name and not name.endswith("/"):
                info[name] = zf.read(name).decode()
    return info


class TestWheelContainsEntryPointModule:
    """Criterion 1a: Wheel memuat modul entry point yang dirujuk metadata."""

    def test_entry_point_module_present(self, wheel_names: list[str]) -> None:
        """apiKeyScan.py must be a top-level member of the wheel."""
        assert "apiKeyScan.py" in wheel_names, (
            "apiKeyScan.py missing from wheel — entry point module not packaged. "
            "Check [tool.setuptools] py-modules in pyproject.toml."
        )

    def test_core_package_present(self, wheel_names: list[str]) -> None:
        """core/__init__.py must be present so the package is importable."""
        assert "core/__init__.py" in wheel_names

    def test_scanners_package_present(self, wheel_names: list[str]) -> None:
        """scanners/__init__.py must be present so the package is importable."""
        assert "scanners/__init__.py" in wheel_names

    def test_core_modules_present(self, wheel_names: list[str]) -> None:
        """All core/*.py modules should be packaged."""
        expected = {
            "core/base_scanner.py",
            "core/config.py",
            "core/key_detector.py",
            "core/notifier.py",
            "core/plugin_loader.py",
            "core/redaction.py",
            "core/report_engine.py",
            "core/transport.py",
            "core/vault.py",
        }
        missing = expected - set(wheel_names)
        assert not missing, f"Missing core modules from wheel: {missing}"

    def test_scanner_modules_present(self, wheel_names: list[str]) -> None:
        """All scanners/*.py modules should be packaged."""
        expected = {
            "scanners/aws_scanner.py",
            "scanners/azure_scanner.py",
            "scanners/github_scanner.py",
            "scanners/google_scanner.py",
            "scanners/openai_scanner.py",
            "scanners/stripe_scanner.py",
            "scanners/twilio_scanner.py",
        }
        missing = expected - set(wheel_names)
        assert not missing, f"Missing scanner modules from wheel: {missing}"


class TestWheelEntryPointMetadata:
    """Criterion 1b: entry_points.txt declares the console script."""

    def test_entry_points_file_exists(self, wheel_dist_info: dict[str, str]) -> None:
        """entry_points.txt must exist in the dist-info directory."""
        ep_files = [k for k in wheel_dist_info if k.endswith("entry_points.txt")]
        assert len(ep_files) == 1, f"Expected one entry_points.txt, got: {ep_files}"
        content = wheel_dist_info[ep_files[0]]
        assert "[console_scripts]" in content
        assert "apikeyscan = apiKeyScan:main" in content

    def test_top_level_lists_entry_module(self, wheel_dist_info: dict[str, str]) -> None:
        """top_level.txt must list apiKeyScan so importlib can discover it."""
        tl_files = [k for k in wheel_dist_info if k.endswith("top_level.txt")]
        assert len(tl_files) == 1
        content = wheel_dist_info[tl_files[0]]
        top_modules = {line.strip() for line in content.splitlines() if line.strip()}
        assert "apiKeyScan" in top_modules
        assert "core" in top_modules
        assert "scanners" in top_modules


class TestWheelMetadata:
    """Criterion 1c: METADATA declares correct name, version, and deps."""

    def test_metadata_name_and_version(self, wheel_dist_info: dict[str, str]) -> None:
        """METADATA must declare Name: apikeyscan and Version: 2.0.0."""
        meta_files = [k for k in wheel_dist_info if k.endswith("METADATA")]
        assert len(meta_files) == 1
        content = wheel_dist_info[meta_files[0]]
        assert "Name: apikeyscan" in content
        assert "Version: 2.0.0" in content

    def test_metadata_requires_python(self, wheel_dist_info: dict[str, str]) -> None:
        """METADATA must declare Requires-Python: >=3.10."""
        meta_files = [k for k in wheel_dist_info if k.endswith("METADATA")]
        content = wheel_dist_info[meta_files[0]]
        assert "Requires-Python: >=3.10" in content

    def test_metadata_declares_runtime_deps(self, wheel_dist_info: dict[str, str]) -> None:
        """METADATA must declare the runtime dependencies."""
        meta_files = [k for k in wheel_dist_info if k.endswith("METADATA")]
        content = wheel_dist_info[meta_files[0]]
        for dep in ["aiohttp", "colorama", "pyyaml", "boto3", "cryptography"]:
            assert dep in content, f"Dependency {dep} not declared in METADATA"


class TestWheelRecordIntegrity:
    """Criterion 1d: RECORD lists all files and is self-consistent."""

    def test_record_exists(self, wheel_dist_info: dict[str, str]) -> None:
        """RECORD file must exist in dist-info."""
        record_files = [k for k in wheel_dist_info if k.endswith("RECORD")]
        assert len(record_files) == 1

    def test_record_lists_all_members(self, wheel_names: list[str], wheel_dist_info: dict[str, str]) -> None:
        """Every archive member (except RECORD itself) must appear in RECORD."""
        record_files = [k for k in wheel_dist_info if k.endswith("RECORD")]
        record_content = wheel_dist_info[record_files[0]]
        record_paths = {line.split(",")[0] for line in record_content.splitlines() if line.strip()}
        for name in wheel_names:
            if name.endswith("RECORD"):
                continue
            assert name in record_paths, f"{name} not listed in RECORD"


class TestEntryPointModuleImportable:
    """Criterion 1e: the entry point module can be imported from the wheel."""

    def test_entry_module_has_main_attr(self, built_wheel: Path, tmp_path: Path) -> None:
        """Extract wheel to temp dir and verify apiKeyScan.main is callable.

        This proves the module referenced by entry_points.txt is not only
        present but importable and exposes the declared ``main`` function.
        Import is done in an isolated subprocess to avoid polluting the
        test process's sys.modules.
        """
        extract_dir = tmp_path / "wheel_extract"
        extract_dir.mkdir()
        with zipfile.ZipFile(built_wheel) as zf:
            zf.extractall(extract_dir)

        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import sys; "
                    f"sys.path.insert(0, r'{extract_dir}'); "
                    "import apiKeyScan; "
                    "assert callable(apiKeyScan.main), 'main is not callable'; "
                    "print('OK')"
                ),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(extract_dir),
        )
        assert (
            result.returncode == 0
        ), f"Entry point module import failed:\nstdout={result.stdout}\nstderr={result.stderr}"
        assert "OK" in result.stdout


@pytest.fixture(scope="module")
def isolated_venv(built_wheel: Path, tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """Create an isolated venv, install the wheel with --no-deps.

    Uses ``--system-site-packages`` so already-installed dependencies
    (aiohttp, colorama, pyyaml, boto3, cryptography) are visible without
    network access.  Returns (entry_exe, run_dir) where run_dir is outside
    the project checkout.
    """
    venv_dir = tmp_path_factory.mktemp("b15_venv")
    result = subprocess.run(
        [sys.executable, "-m", "venv", "--system-site-packages", str(venv_dir)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"venv creation failed: {result.stderr}"

    import os

    if os.name == "nt":
        pip_exe = venv_dir / "Scripts" / "pip.exe"
        entry_exe = venv_dir / "Scripts" / "apikeyscan.exe"
    else:
        pip_exe = venv_dir / "bin" / "pip"
        entry_exe = venv_dir / "bin" / "apikeyscan"

    result = subprocess.run(
        [str(pip_exe), "install", "--no-deps", str(built_wheel)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"Wheel install failed: {result.stderr}"

    run_dir = tmp_path_factory.mktemp("b15_outside_checkout")
    return entry_exe, run_dir


class TestIsolatedInstallEntryPoint:
    """Criterion 2: Console entry point works from outside checkout in isolated venv."""

    def test_help_succeeds_outside_checkout(self, isolated_venv: tuple[Path, Path]) -> None:
        """``apikeyscan --help`` exits 0 and shows usage from outside checkout."""
        entry_exe, run_dir = isolated_venv
        result = subprocess.run(
            [str(entry_exe), "--help"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(run_dir),
        )
        assert result.returncode == 0, f"--help failed:\nstdout={result.stdout}\nstderr={result.stderr}"
        assert "usage:" in result.stdout.lower()
        assert "apikeyscan" in result.stdout.lower()

    def test_list_checks_succeeds_outside_checkout(self, isolated_venv: tuple[Path, Path]) -> None:
        """``apikeyscan list-checks`` exits 0 and lists providers from outside checkout."""
        entry_exe, run_dir = isolated_venv
        result = subprocess.run(
            [str(entry_exe), "list-checks"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(run_dir),
        )
        assert result.returncode == 0, f"list-checks failed:\nstdout={result.stdout}\nstderr={result.stderr}"
        assert "google" in result.stdout.lower() or "scanner" in result.stdout.lower()
