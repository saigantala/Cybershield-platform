import os
import sys
from pathlib import Path
import pytest

if __name__ == "__main__":
    backend_dir = Path(__file__).resolve().parent
    os.chdir(backend_dir)
    sys.path.insert(0, str(backend_dir))
    args = sys.argv[1:] if len(sys.argv) > 1 else ["tests/test_scans.py"]
    code = pytest.main(["-v", "-s", *args])
    sys.exit(code)
