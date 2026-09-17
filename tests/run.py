#!/usr/bin/env python3
"""Run the Mailu Tools test suite.

No Mailu server, no Docker and no network access are required: every external
input comes from a fixture in tests/fixtures.

Usage:
    tests/run.py                # everything
    tests/run.py test_scopes    # one module
    tests/run.py -v             # verbose
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

# Never let a developer's real configuration or systemd leak into a test run.
os.environ.pop("MAILUT_CONF", None)
os.environ.pop("MAILUT_ROOT", None)
os.environ["MAILUT_NO_SYSTEMD"] = "1"


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    verbosity = 2 if "-v" in argv else 1
    names = [a for a in argv if not a.startswith("-")]

    loader = unittest.TestLoader()
    if names:
        suite = unittest.TestSuite(loader.loadTestsFromName(name) for name in names)
    else:
        suite = loader.discover(str(ROOT / "tests"), pattern="test_*.py", top_level_dir=str(ROOT / "tests"))

    result = unittest.TextTestRunner(verbosity=verbosity, buffer=False).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
