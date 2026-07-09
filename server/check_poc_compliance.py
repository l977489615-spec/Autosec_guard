#!/usr/bin/env python3
"""
AutoSec Guard — PoC 脚本合规检查器
用法: python3 check_poc_compliance.py [--fix] [--csv report.csv] [path/to/pocs]

检查规则依据 POC_TEMPLATE_SPEC.md v1.0
"""
from __future__ import annotations

import argparse
import ast
import csv
import importlib.util
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ── 合规等级 ─────────────────────────────────────────────────
SEVERITY_ERROR   = "ERROR"
SEVERITY_WARNING = "WARNING"
SEVERITY_INFO    = "INFO"

# ── 硬件依赖关键词（判断 Type-B） ─────────────────────────────
HW_KEYWORDS = re.compile(
    r"nRF52840|wdissector|fragattack|braktooth|sweyntooth|socketcan|"
    r"can_bus_utils|hackrf|ubertooth|rfcat|yard.stick|monitor_mode|"
    r"wpa_supplicant.*monitor|airodump|hostapd.*monitor|hcitool|"
    r"requires_rf_hardware|HW_REQUIREMENTS",
    re.I,
)

REQUIRED_VULN_FIELDS = [
    "id", "cve", "year", "domain", "vendor_product",
    "component", "type", "summary", "source_url", "affected",
]

REQUIRED_META_ATTRS = [
    "meta_display_id", "meta_poc_name", "meta_cve_id",
    "meta_source_url", "meta_references", "meta_severity",
    "meta_protocol", "meta_target_os", "meta_required_params",
    "is_disruptive", "meta_destructive_level",
]

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}
VALID_LEVELS     = {"Safe", "Restart", "DataLoss", "Brick"}


@dataclass
class Issue:
    severity: str
    code: str
    message: str


@dataclass
class ScriptReport:
    path: Path
    script_type: str = "unknown"     # Type-A / Type-B / unknown
    issues: list[Issue] = field(default_factory=list)

    @property
    def error_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == SEVERITY_ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == SEVERITY_WARNING)

    @property
    def compliant(self) -> bool:
        return self.error_count == 0

    def add(self, severity: str, code: str, message: str):
        self.issues.append(Issue(severity, code, message))


# ─────────────────────────────────────────────────────────────
# 检查函数
# ─────────────────────────────────────────────────────────────

def _detect_type(src: str) -> str:
    """判断脚本类型：Type-A（标准审计）or Type-B（硬件依赖）。"""
    if HW_KEYWORDS.search(src):
        return "Type-B"
    if re.search(r'^VULN\s*=', src, re.M) or re.search(r'run_active_validation', src):
        return "Type-A"
    if re.search(r'^class \w+\(.*Plugin', src, re.M):
        return "Type-A"   # 默认归 A
    return "unknown"


def check_shebang(src: str, report: ScriptReport):
    if not src.startswith("#!/usr/bin/env python3"):
        report.add(SEVERITY_ERROR, "E001", "缺少 shebang: #!/usr/bin/env python3")


def check_docstring(src: str, report: ScriptReport):
    # 移除 shebang 行后检查第一个 token 是否为 docstring
    stripped = src
    if stripped.startswith("#!"):
        stripped = stripped[stripped.index("\n") + 1:]
    stripped = stripped.lstrip("\n")
    if not (stripped.startswith('"""') or stripped.startswith("'''")):
        report.add(SEVERITY_ERROR, "E002", "缺少模块级 docstring（应紧跟 shebang 之后）")
        return
    # 检查 docstring 内容
    for field_name in ["PoC Name", "CVE", "Category", "Severity"]:
        if field_name not in src[:2000]:
            report.add(SEVERITY_WARNING, "W001", f"模块 docstring 缺少字段: {field_name}")


def check_future_import(src: str, report: ScriptReport):
    if "from __future__ import annotations" not in src:
        report.add(SEVERITY_WARNING, "W002", "缺少 'from __future__ import annotations'")


def check_vuln_dict(src: str, report: ScriptReport):
    if not re.search(r'^VULN\s*=\s*\{', src, re.M):
        report.add(SEVERITY_ERROR, "E003", "缺少顶级 VULN 字典")
        return

    # 尝试从 VULN 块中抽取内容进行字段检查
    try:
        # 找到 VULN = { ... } 并提取
        m = re.search(r'^(VULN\s*=\s*\{)', src, re.M)
        if not m:
            return
        start = m.start()
        # 用括号计数
        depth = 0
        end = start
        in_str = False
        str_char = None
        for i in range(start, len(src)):
            c = src[i]
            if in_str:
                if c == "\\" and i + 1 < len(src):
                    continue
                if c == str_char:
                    in_str = False
            else:
                if c in ('"', "'"):
                    in_str = True
                    str_char = c
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break

        vuln_src = src[start:end]
        # 安全地 eval（仅允许字面量）
        vuln_val = ast.literal_eval(vuln_src[vuln_src.index("{"):])
        for fld in REQUIRED_VULN_FIELDS:
            if fld not in vuln_val:
                report.add(SEVERITY_ERROR, "E004", f"VULN 缺少必填字段: '{fld}'")

        # 检查 affected 版本格式
        for entry in vuln_val.get("affected", []):
            for ver in entry.get("versions", []):
                if isinstance(ver, str):
                    report.add(SEVERITY_ERROR, "E005",
                               "VULN['affected']['versions'] 不得使用字符串，请改为字典格式")
                    break

        # id 一致性（只检查是否存在）
        if not isinstance(vuln_val.get("id"), int):
            report.add(SEVERITY_WARNING, "W003", "VULN['id'] 应为整数")

    except Exception:
        report.add(SEVERITY_WARNING, "W004", "VULN 字典解析失败（可能包含运行时表达式），跳过字段检查")


def check_hw_requirements(src: str, report: ScriptReport):
    if "HW_REQUIREMENTS" not in src:
        report.add(SEVERITY_ERROR, "E006", "Type-B 脚本缺少 HW_REQUIREMENTS 字典")
        return
    # 检查必填键
    for key in ["hardware", "connection", "tools", "firmware", "setup"]:
        if f'"{key}"' not in src and f"'{key}'" not in src:
            report.add(SEVERITY_WARNING, "W005", f"HW_REQUIREMENTS 可能缺少键: '{key}'")


def check_run_poc(src: str, report: ScriptReport):
    if not re.search(r'^def _run_poc\s*\(', src, re.M):
        report.add(SEVERITY_ERROR, "E007", "缺少 _run_poc(plugin, ...) 探针函数")
        return
    if "detection_confidence" not in src:
        report.add(SEVERITY_ERROR, "E008", "_run_poc 未调用 detection_confidence()")
    # 检查 allow_disruptive
    if "allow_disruptive" not in src:
        report.add(SEVERITY_WARNING, "W006", "_run_poc 未响应 allow_disruptive 参数")
    # 检查超时
    if not re.search(r'timeout\s*=', src):
        report.add(SEVERITY_WARNING, "W007", "未发现显式超时设置（timeout=...）")


def check_plugin_class(src: str, report: ScriptReport):
    if not re.search(r'^class \w+\(.*IVIVulnerabilityPlugin\)', src, re.M):
        report.add(SEVERITY_ERROR, "E009", "缺少继承自 IVIVulnerabilityPlugin 的 Plugin 类")
        return
    for attr in REQUIRED_META_ATTRS:
        if attr not in src:
            report.add(SEVERITY_ERROR, "E010", f"Plugin 类缺少必填属性: {attr}")

    # meta_severity 枚举检查
    m = re.search(r'meta_severity\s*=\s*["\'](\w+)["\']', src)
    if m and m.group(1) not in VALID_SEVERITIES:
        report.add(SEVERITY_WARNING, "W008",
                   f"meta_severity='{m.group(1)}' 不在允许值 {VALID_SEVERITIES} 中")

    # meta_destructive_level 枚举检查
    m = re.search(r'meta_destructive_level\s*=\s*["\'](\w+)["\']', src)
    if m and m.group(1) not in VALID_LEVELS:
        report.add(SEVERITY_WARNING, "W009",
                   f"meta_destructive_level='{m.group(1)}' 不在允许值 {VALID_LEVELS} 中")

    # exploit 方法
    if "def exploit(" not in src:
        report.add(SEVERITY_ERROR, "E011", "Plugin 类缺少 exploit() 方法")

    # check_prerequisites 方法
    if "def check_prerequisites(" not in src:
        report.add(SEVERITY_ERROR, "E012", "Plugin 类缺少 check_prerequisites() 方法")

    # run_active_validation (Type-A)
    if report.script_type == "Type-A" and "run_active_validation" not in src:
        report.add(SEVERITY_WARNING, "W010", "Type-A 脚本 exploit() 未调用 run_active_validation()")


def check_main_block(src: str, report: ScriptReport):
    if not re.search(r'^if __name__\s*==\s*["\']__main__["\']', src, re.M):
        report.add(SEVERITY_WARNING, "W011", "缺少 __main__ 入口块")
        return
    if "json.dumps" not in src and "json_result" not in src:
        report.add(SEVERITY_INFO, "I001",
                   "__main__ 输出建议改用 json.dumps(result, ...)")
    if "--disruptive" not in src and "disruptive" not in src:
        report.add(SEVERITY_INFO, "I002",
                   "__main__ 建议添加 --disruptive 参数")


def check_bad_patterns(src: str, report: ScriptReport):
    """检测禁止写法。"""
    # vulnerable = "yes" 等非布尔
    for m in re.finditer(r'vulnerable\s*=\s*["\'](\w+)["\']', src):
        if m.group(1) not in ("True", "False", "None", "true", "false"):
            report.add(SEVERITY_ERROR, "E013",
                       f"'vulnerable' 赋值为非布尔字符串: \"{m.group(1)}\"")
    # 顶层 socket/requests 调用
    if re.search(r'^(socket\.connect|requests\.(get|post))\(', src, re.M):
        report.add(SEVERITY_ERROR, "E014",
                   "模块顶层存在网络调用，必须移入函数内部")


# ─────────────────────────────────────────────────────────────
# 主检查入口
# ─────────────────────────────────────────────────────────────

def check_script(py_path: Path) -> ScriptReport:
    report = ScriptReport(path=py_path)
    try:
        src = py_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        report.add(SEVERITY_ERROR, "E000", f"读取文件失败: {e}")
        return report

    report.script_type = _detect_type(src)

    check_shebang(src, report)
    check_docstring(src, report)
    check_future_import(src, report)
    check_bad_patterns(src, report)
    check_plugin_class(src, report)
    check_main_block(src, report)

    if report.script_type == "Type-A":
        check_vuln_dict(src, report)
        check_run_poc(src, report)
    elif report.script_type == "Type-B":
        check_hw_requirements(src, report)

    return report


# ─────────────────────────────────────────────────────────────
# 批量修复（轻量级，只修复机械性问题）
# ─────────────────────────────────────────────────────────────

def _fix_shebang(src: str) -> str:
    if not src.startswith("#!/usr/bin/env python3"):
        src = "#!/usr/bin/env python3\n" + src
    return src


def _fix_future_import(src: str) -> str:
    if "from __future__ import annotations" in src:
        return src
    # 在第一个非 shebang/docstring import 前插入
    m = re.search(r'^(import |from )', src, re.M)
    if m:
        return src[:m.start()] + "from __future__ import annotations\n\n" + src[m.start():]
    return src


def _fix_main_block(src: str, py_path: Path) -> str:
    """添加最简 __main__ 块。"""
    if re.search(r'^if __name__', src, re.M):
        return src
    # 找到 Plugin 类名
    m = re.search(r'^class (\w+Plugin)\(', src, re.M)
    class_name = m.group(1) if m else "UnknownPlugin"
    # 判断参数
    has_vuln = re.search(r'^VULN\s*=', src, re.M)
    main_block = f'''
if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "{py_path.stem}") if "VULN" in dir() else "{py_path.stem}"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = {class_name}({{
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    }})
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))
'''
    return src.rstrip() + "\n" + main_block


def fix_script(py_path: Path, issues: list[Issue]) -> int:
    """返回实际修复的数量。"""
    src = py_path.read_text(encoding="utf-8", errors="replace")
    original = src
    fixed_count = 0

    codes = {i.code for i in issues}

    if "E001" in codes:
        src = _fix_shebang(src)
        fixed_count += 1

    if "W002" in codes:
        src = _fix_future_import(src)
        fixed_count += 1

    if "W011" in codes:
        src = _fix_main_block(src, py_path)
        fixed_count += 1

    if src != original:
        py_path.write_text(src, encoding="utf-8")

    return fixed_count


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

def run_compliance_check(
    pocs_dir: Path,
    fix: bool = False,
    csv_path: Optional[Path] = None,
    json_path: Optional[Path] = None,
    min_severity: str = SEVERITY_WARNING,
) -> dict:
    scripts = sorted(p for p in pocs_dir.glob("**/*.py") if p.name[0].isdigit())
    reports: list[ScriptReport] = []

    sev_order = {SEVERITY_ERROR: 0, SEVERITY_WARNING: 1, SEVERITY_INFO: 2}
    min_order = sev_order.get(min_severity, 1)

    for py in scripts:
        report = check_script(py)
        reports.append(report)

        if fix and report.issues:
            fix_script(py, report.issues)

    # ── 统计 ───────────────────────────────────────────────
    total        = len(reports)
    compliant    = sum(1 for r in reports if r.compliant)
    type_a       = sum(1 for r in reports if r.script_type == "Type-A")
    type_b       = sum(1 for r in reports if r.script_type == "Type-B")
    errors_total = sum(r.error_count for r in reports)
    warn_total   = sum(r.warning_count for r in reports)

    print("=" * 72)
    print("  AutoSec Guard — PoC 合规检查报告")
    print("=" * 72)
    print(f"  扫描脚本总数   : {total}")
    print(f"  Type-A 标准    : {type_a}")
    print(f"  Type-B 硬件依赖: {type_b}")
    print(f"  完全合规       : {compliant} ({compliant * 100 // total if total else 0}%)")
    print(f"  ERROR 总计     : {errors_total}")
    print(f"  WARNING 总计   : {warn_total}")
    print()

    # ── 每个不合规脚本的详情 ───────────────────────────────
    non_compliant = [r for r in reports if not r.compliant]
    if non_compliant:
        print(f"── 不合规脚本（{len(non_compliant)} 个）{'（已尝试自动修复）' if fix else ''} ─────")
        for r in non_compliant:
            rel = r.path.relative_to(pocs_dir)
            print(f"\n  [{r.script_type}] {rel}")
            for issue in r.issues:
                if sev_order.get(issue.severity, 99) <= min_order:
                    icon = "✗" if issue.severity == SEVERITY_ERROR else "⚠"
                    print(f"    {icon} [{issue.severity}] {issue.code}: {issue.message}")
    else:
        print("  所有脚本完全合规！")

    # ── 最常见问题 TOP 10 ──────────────────────────────────
    from collections import Counter
    all_codes = Counter(
        issue.code
        for r in reports
        for issue in r.issues
        if sev_order.get(issue.severity, 99) <= min_order
    )
    if all_codes:
        print("\n── 最常见问题 TOP 10 ─────────────────────────────────────")
        for code, cnt in all_codes.most_common(10):
            # 找到对应 message
            msg = next((i.message for r in reports for i in r.issues if i.code == code), "")
            print(f"  {code:6s}  {cnt:4d}×  {msg[:60]}")

    print("=" * 72)

    # ── CSV 输出 ───────────────────────────────────────────
    if csv_path:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["file", "type", "compliant", "errors", "warnings",
                        "code", "severity", "message"])
            for r in reports:
                rel = str(r.path.relative_to(pocs_dir))
                if r.issues:
                    for issue in r.issues:
                        w.writerow([rel, r.script_type, r.compliant,
                                    r.error_count, r.warning_count,
                                    issue.code, issue.severity, issue.message])
                else:
                    w.writerow([rel, r.script_type, True, 0, 0, "", "", ""])
        print(f"  CSV: {csv_path}")

    # ── JSON 输出 ─────────────────────────────────────────
    if json_path:
        payload = {
            "summary": {
                "total": total, "compliant": compliant,
                "type_a": type_a, "type_b": type_b,
                "errors": errors_total, "warnings": warn_total,
                "compliance_pct": compliant * 100 // total if total else 0,
            },
            "scripts": [
                {
                    "file":      str(r.path.relative_to(pocs_dir)),
                    "type":      r.script_type,
                    "compliant": r.compliant,
                    "errors":    r.error_count,
                    "warnings":  r.warning_count,
                    "issues":    [{"severity": i.severity,
                                   "code": i.code,
                                   "message": i.message}
                                  for i in r.issues],
                }
                for r in reports
            ],
        }
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
        print(f"  JSON: {json_path}")

    return {
        "total": total, "compliant": compliant,
        "compliance_pct": compliant * 100 // total if total else 0,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "pocs_dir", nargs="?", default="pocs",
        help="PoC 脚本目录（默认 ./pocs）",
    )
    parser.add_argument(
        "--fix", action="store_true",
        help="自动修复可机械修复的问题（shebang / future import / __main__）",
    )
    parser.add_argument("--csv",  type=Path, help="输出 CSV 报告路径")
    parser.add_argument("--json", type=Path, help="输出 JSON 报告路径")
    parser.add_argument(
        "--min-severity", default="WARNING",
        choices=["ERROR", "WARNING", "INFO"],
        help="显示的最低严重级别（默认 WARNING）",
    )
    args = parser.parse_args()

    pocs_dir = Path(args.pocs_dir).resolve()
    if not pocs_dir.exists():
        print(f"错误：目录不存在: {pocs_dir}", file=sys.stderr)
        sys.exit(1)

    result = run_compliance_check(
        pocs_dir,
        fix=args.fix,
        csv_path=args.csv,
        json_path=args.json,
        min_severity=args.min_severity,
    )
    sys.exit(0 if result["compliance_pct"] == 100 else 1)


if __name__ == "__main__":
    main()
