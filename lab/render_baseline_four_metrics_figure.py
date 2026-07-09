#!/usr/bin/env python3
"""Render 基线方法四指标对比 — Fig.1 data/labels, Fig.2 bar colors and spacing."""

from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "tmp" / "docs" / "baseline_four_metrics_figure.png"

# Fig.1 data and metric names (unchanged)
SYSTEMS = [
    ("PentestGPT", [46.7, 60.0, 58.7, 16.43]),
    ("普通 Multi-Agent", [66.7, 70.0, 62.5, 10.26]),
    ("EDVV", [86.7, 93.3, 95.3, 14.73]),
]
METRICS = [
    ("基准阳性召回率（%）", "#4285F4"),
    ("基准子任务完成率（%）", "#34A853"),
    ("证据完整率（%）", "#FBBC05"),
    ("平均端到端净耗时（min）", "#EA4335"),
]

# Fig.2 layout: bars touch inside each group; wide gap between groups
BAR_WIDTH = 56
INTRA_GROUP_GAP = 0
GROUP_CENTERS = (270, 600, 930)


def load_font(size: int, *, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/STHeiti Light.ttc",
        "/Library/Fonts/Arial Unicode.ttf",
    ]
    for path in candidates:
        if Path(path).is_file():
            try:
                return ImageFont.truetype(path, size=size, index=1 if bold else 0)
            except OSError:
                return ImageFont.truetype(path, size=size)
    return ImageFont.load_default()


def render_figure(output: Path) -> Path:
    width, height = 1200, 700
    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)

    title_font = load_font(34, bold=True)
    label_font = load_font(24)
    axis_font = load_font(19)
    note_font = load_font(18)

    title = "基线方法四指标对比"
    title_box = draw.textbbox((0, 0), title, font=title_font)
    draw.text(((width - (title_box[2] - title_box[0])) / 2, 32), title, fill="#111827", font=title_font)

    left, top, right, bottom = 110, 150, 1090, 580
    for percent in range(0, 101, 20):
        y = bottom - (bottom - top) * percent / 100
        draw.line((left, y, right, y), fill="#D8E1EB", width=2)
        draw.text((48, y - 11), f"{percent}%", fill="#334155", font=axis_font)
    draw.line((left, top, left, bottom), fill="#64748B", width=2)
    draw.line((left, bottom, right, bottom), fill="#64748B", width=2)

    legend_x = 70
    for metric, color in METRICS:
        draw.rectangle((legend_x, 96, legend_x + 18, 114), fill=color, outline="#334155", width=1)
        draw.text((legend_x + 26, 90), metric, fill="#111827", font=axis_font)
        legend_x += 270

    group_width = len(METRICS) * BAR_WIDTH + (len(METRICS) - 1) * INTRA_GROUP_GAP
    for (system_label, values), center in zip(SYSTEMS, GROUP_CENTERS):
        start_x = center - group_width / 2
        for metric_index, (_, color) in enumerate(METRICS):
            value = values[metric_index]
            x1 = start_x + metric_index * (BAR_WIDTH + INTRA_GROUP_GAP)
            x2 = x1 + BAR_WIDTH
            bar_top = bottom - (bottom - top) * value / 100
            draw.rectangle((x1, bar_top, x2, bottom), fill=color, outline="#334155", width=2)
            value_text = f"{value:.2f}" if metric_index == 3 else f"{value:.1f}"
            value_box = draw.textbbox((0, 0), value_text, font=axis_font)
            draw.text(
                ((x1 + x2) / 2 - (value_box[2] - value_box[0]) / 2, bar_top - 26),
                value_text,
                fill="#111827",
                font=axis_font,
            )
        label_box = draw.textbbox((0, 0), system_label, font=label_font)
        draw.text((center - (label_box[2] - label_box[0]) / 2, bottom + 22), system_label, fill="#111827", font=label_font)

    note = "注：前三项为百分比指标；平均端到端净耗时单位为 min，数值越低表示验证越快。"
    note_box = draw.textbbox((0, 0), note, font=note_font)
    draw.text(((width - (note_box[2] - note_box[0])) / 2, 642), note, fill="#475569", font=note_font)

    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output)
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    path = render_figure(args.output)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
