import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from otadump._artifact import executable


result = subprocess.run([executable(), "--help"], text=True, capture_output=True, check=False)
assert result.returncode == 1  # gflags uses status 1 after printing help.
assert "system/update_engine/aosp/ota_extractor.cc" in result.stdout
assert "input_dir" in result.stdout
assert "single_thread" in result.stdout
