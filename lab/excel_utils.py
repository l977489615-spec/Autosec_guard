"""Excel 写入辅助：清理 openpyxl 不允许的控制字符。"""
from __future__ import annotations

import re
from typing import Any

# 与 openpyxl.cell.cell.ILLEGAL_CHARACTERS_RE 一致
_ILLEGAL_CHARACTERS_RE = re.compile(r"[\000-\010|\013-\014|\016-\037]")


def sanitize_excel_value(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    text = _ILLEGAL_CHARACTERS_RE.sub("", str(value))
    if len(text) > 32767:
        return text[:32767]
    return text
