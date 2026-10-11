"""Run the repository static extractor under Python isolated mode."""

from pathlib import Path
import runpy
import sys


if not sys.flags.isolated:
    raise SystemExit("Run this wrapper with Python -I.")

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))
runpy.run_module(
    "v5_server.tools.static_protocol.cli",
    run_name="__main__",
    alter_sys=True,
)
