#!/usr/bin/env python3
"""Entry point for the ZCode upload forensics collector.

    python3 scripts/diagnose.py --out ./zcode-upload-report.html

All logic lives in the sibling `zcode_forensics` package — keep the files
together when copying this skill around.
"""

from __future__ import annotations

import sys

from zcode_forensics.cli import main

if __name__ == "__main__":
    sys.exit(main())
