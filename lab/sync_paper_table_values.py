#!/usr/bin/env python3
"""Update table 7/8 data cells in-place, preserving existing workbook layout and styles."""

from __future__ import annotations

import json
import shutil
from copy import copy
from pathlib import Path

from openpyxl import load_workbook
from openpyxl.worksheet.worksheet import Worksheet


ROOT = Path(__file__).resolve().parents[1]
STRICT_DATA = ROOT / "lab" / "final_paper_data_strict"
DEFAULT_PAPER_BOOK = Path("/Users/queen/Desktop/ICV_POC_research/论文/论文内表格（新）.xlsx")
SUMMARY_BOOK = ROOT / "lab" / "论文实验数据汇总.xlsx"

TABLE7_SHEET = "表7_智能体消融"
TABLE8_SHEET = "表8_模型对比"

TABLE7_HEADER_RENAMES = {
    "完成任务数/总任务数": "Agent命中阳性数/基准阳性PoC数",
    "综合任务完成率": "阳性召回率",
}

TABLE8_HEADER_RENAMES = {
    "基准阳性召回率": "阳性召回率",
    "GT命中数/GT阳性数": "Agent命中阳性数/基准阳性PoC数",
    "执行 PoC 总数": "已执行数量",
    "发现数合计": "Agent命中阳性数",
}

TABLE7_FIELDS = {
    "组别": "组别",
    "系统配置": "系统配置",
    "Agent命中阳性数/基准阳性PoC数": "Agent命中阳性数/基准阳性PoC数",
    "阳性召回率": "阳性召回率",
    "证据归档率": "证据归档率",
    "平均人工干预次数": "平均人工干预次数",
    "平均任务耗时": "平均任务耗时",
    "data_source": "data_source",
}

TABLE8_FIELDS = {
    "模型": "模型",
    "类型": "类型",
    "阳性召回率": "阳性召回率",
    "有效证据率": "有效证据率",
    "平均任务耗时": "平均任务耗时",
    "高风险误触发次数": "高风险误触发次数",
    "目标数量": "目标数量",
    "Agent命中阳性数/基准阳性PoC数": "Agent命中阳性数/基准阳性PoC数",
    "已执行数量": "已执行数量",
    "Agent命中阳性数": "Agent命中阳性数",
    "Total Tokens 合计": "Total Tokens 合计",
    "平均每目标 Tokens": "平均每目标 Tokens",
    "总耗时": "总耗时",
    "variant_id": "variant_id",
    "data_source": "data_source",
}


def strict_rows(name: str) -> list[dict]:
    payload = json.loads((STRICT_DATA / f"{name}.json").read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError(f"严格汇总数据格式错误: {name}")
    return payload


def header_columns(ws: Worksheet) -> dict[str, int]:
    columns: dict[str, int] = {}
    for col in range(1, ws.max_column + 1):
        header = ws.cell(1, col).value
        if header is not None and str(header).strip():
            columns[str(header).strip()] = col
    return columns


def rename_headers(ws: Worksheet, rename_map: dict[str, str]) -> None:
    for col in range(1, ws.max_column + 1):
        header = ws.cell(1, col).value
        if header is None:
            continue
        text = str(header).strip()
        if text in rename_map:
            ws.cell(1, col, rename_map[text])


def update_rows_by_key(
    ws: Worksheet,
    rows: list[dict],
    *,
    key_header: str,
    field_map: dict[str, str],
    json_key: str,
) -> int:
    columns = header_columns(ws)
    key_col = columns.get(key_header)
    if not key_col:
        raise ValueError(f"工作表 {ws.title} 缺少关键列: {key_header}")

    updated = 0
    for item in rows:
        key_value = item.get(json_key)
        if key_value is None:
            continue
        for row_idx in range(2, ws.max_row + 1):
            if ws.cell(row_idx, key_col).value != key_value:
                continue
            for excel_header, json_field in field_map.items():
                col = columns.get(excel_header)
                if col is None:
                    continue
                if json_field in item:
                    ws.cell(row_idx, col, item[json_field])
            updated += 1
            break
    return updated


def copy_cell_style(source_cell, target_cell) -> None:
    target_cell.font = copy(source_cell.font)
    target_cell.fill = copy(source_cell.fill)
    target_cell.border = copy(source_cell.border)
    target_cell.alignment = copy(source_cell.alignment)
    target_cell.number_format = source_cell.number_format
    target_cell.protection = copy(source_cell.protection)


def copy_worksheet(source_ws: Worksheet, target_wb, name: str, index: int) -> Worksheet:
    if name in target_wb.sheetnames:
        target_wb.remove(target_wb[name])
    target_ws = target_wb.create_sheet(name, index)
    for row in source_ws.iter_rows():
        for cell in row:
            target_cell = target_ws.cell(cell.row, cell.column, cell.value)
            copy_cell_style(cell, target_cell)
    for col, dim in source_ws.column_dimensions.items():
        target_ws.column_dimensions[col].width = dim.width
    target_ws.freeze_panes = source_ws.freeze_panes
    target_ws.sheet_view.showGridLines = source_ws.sheet_view.showGridLines
    return target_ws


def update_paper_workbook(path: Path) -> dict[str, int]:
    wb = load_workbook(path)
    if TABLE7_SHEET not in wb.sheetnames or TABLE8_SHEET not in wb.sheetnames:
        raise FileNotFoundError(f"{path} 缺少 {TABLE7_SHEET} 或 {TABLE8_SHEET}")

    ws7 = wb[TABLE7_SHEET]
    ws8 = wb[TABLE8_SHEET]
    rename_headers(ws7, TABLE7_HEADER_RENAMES)
    rename_headers(ws8, TABLE8_HEADER_RENAMES)

    table7_count = update_rows_by_key(
        ws7,
        strict_rows("table7_total_by_model_group"),
        key_header="组别",
        field_map=TABLE7_FIELDS,
        json_key="组别",
    )
    table8_count = update_rows_by_key(
        ws8,
        strict_rows("table8_total_by_model"),
        key_header="模型",
        field_map=TABLE8_FIELDS,
        json_key="模型",
    )
    wb.save(path)
    return {"table7_rows": table7_count, "table8_rows": table8_count, "path": str(path)}


def restore_summary_tables_from_paper_book(paper_book: Path = DEFAULT_PAPER_BOOK) -> None:
    if not paper_book.is_file():
        return
    try:
        paper_wb = load_workbook(paper_book)
        summary_wb = load_workbook(SUMMARY_BOOK)
        for sheet_name in (TABLE7_SHEET, TABLE8_SHEET):
            index = (
                summary_wb.sheetnames.index(sheet_name)
                if sheet_name in summary_wb.sheetnames
                else len(summary_wb.sheetnames)
            )
            copy_worksheet(paper_wb[sheet_name], summary_wb, sheet_name, index)
        summary_wb.save(SUMMARY_BOOK)
    except Exception:
        shutil.copy2(paper_book, SUMMARY_BOOK)


def main() -> None:
    paper_book = DEFAULT_PAPER_BOOK
    if not paper_book.is_file():
        raise SystemExit(f"未找到论文表格: {paper_book}")
    result = update_paper_workbook(paper_book)
    restore_summary_tables_from_paper_book(paper_book)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
