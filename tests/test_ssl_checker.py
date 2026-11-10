import os
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "ssl_checker.py"


def run_checker(*argv):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *argv],
        capture_output=True,
        text=True,
    )


def test_empty_host_list_is_a_usage_error():
    """`-H` with no hosts must exit non-zero instead of reporting success."""
    proc = run_checker("-H")
    assert proc.returncode == 2


def test_empty_host_file_is_a_usage_error():
    """An empty `--host-file` must exit non-zero instead of reporting success."""
    with tempfile.NamedTemporaryFile(
        "w", suffix=".txt", delete=False
    ) as host_file:
        host_file.write("# only a comment\n\n")
        path = host_file.name
    try:
        proc = run_checker("-f", path)
    finally:
        os.unlink(path)
    assert proc.returncode == 2
