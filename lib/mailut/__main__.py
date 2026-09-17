"""Allow `python3 -m mailut` in a source checkout."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
