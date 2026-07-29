#!/usr/bin/env python3
"""兼容入口：转发到受控写总闸 `e2e_controlled_write.py`。

保留旧命令，避免既有文档/习惯失效：
  python scripts/e2e_whitelist_write.py --live
等价于：
  python scripts/e2e_controlled_write.py --live
"""
from __future__ import annotations

import runpy
import sys
from pathlib import Path

TARGET = Path(__file__).with_name("e2e_controlled_write.py")
if not TARGET.is_file():
    print(f"FAIL: missing {TARGET}", file=sys.stderr)
    sys.exit(1)

sys.argv[0] = str(TARGET)
runpy.run_path(str(TARGET), run_name="__main__")
