#!/usr/bin/env python3
"""Vendor-only desktop UI for issuing encrypted-key offline licenses.

This application is intentionally separate from the customer workstation and
must never be included in customer artifacts.
"""

from __future__ import annotations

import argparse
import datetime as dt
import re
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from license_cli import issue
from licensing import ALL_FEATURES


class LicenseIssuerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("AutoSec Guard 离线许可证签发器")
        self.geometry("720x520")
        self.minsize(680, 480)

        self.private_key = tk.StringVar()
        self.customer = tk.StringVar()
        self.machine_code = tk.StringVar()
        self.months = tk.StringVar(value="1")
        self.edition = tk.StringVar(value="enterprise")
        self.output_dir = tk.StringVar(value=str(Path.cwd() / "deliveries"))
        self.password = tk.StringVar()
        self.status = tk.StringVar(value="私钥只在本机内存中解锁，不会写入许可证。")
        self._build_ui()

    def _build_ui(self) -> None:
        frame = ttk.Frame(self, padding=20)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)

        ttk.Label(frame, text="供应商离线许可证签发", font=("TkDefaultFont", 17, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 18)
        )
        ttk.Label(frame, text="加密私钥").grid(row=1, column=0, sticky="w", pady=6)
        ttk.Entry(frame, textvariable=self.private_key).grid(row=1, column=1, sticky="ew", padx=10)
        ttk.Button(frame, text="选择…", command=self._choose_key).grid(row=1, column=2)

        ttk.Label(frame, text="私钥口令").grid(row=2, column=0, sticky="w", pady=6)
        password_entry = ttk.Entry(frame, textvariable=self.password, show="●")
        password_entry.grid(row=2, column=1, sticky="ew", padx=10)

        ttk.Label(frame, text="客户名称").grid(row=3, column=0, sticky="w", pady=6)
        ttk.Entry(frame, textvariable=self.customer).grid(row=3, column=1, columnspan=2, sticky="ew", padx=(10, 0))

        ttk.Label(frame, text="客户设备码").grid(row=4, column=0, sticky="nw", pady=6)
        machine_entry = ttk.Entry(frame, textvariable=self.machine_code)
        machine_entry.grid(row=4, column=1, sticky="ew", padx=10)
        ttk.Button(frame, text="从剪贴板粘贴", command=self._paste_machine_code).grid(row=4, column=2)

        ttk.Label(frame, text="授权时长").grid(row=5, column=0, sticky="w", pady=6)
        ttk.Combobox(
            frame,
            textvariable=self.months,
            values=("1", "3", "6", "12", "24", "36"),
            state="readonly",
            width=12,
        ).grid(row=5, column=1, sticky="w", padx=10)
        ttk.Label(frame, text="个月（自然月）").grid(row=5, column=1, sticky="w", padx=(110, 0))

        ttk.Label(frame, text="版本").grid(row=6, column=0, sticky="w", pady=6)
        ttk.Combobox(
            frame, textvariable=self.edition, values=("enterprise", "professional", "trial"), width=18
        ).grid(row=6, column=1, sticky="w", padx=10)

        ttk.Label(frame, text="输出目录").grid(row=7, column=0, sticky="w", pady=6)
        ttk.Entry(frame, textvariable=self.output_dir).grid(row=7, column=1, sticky="ew", padx=10)
        ttk.Button(frame, text="选择…", command=self._choose_output).grid(row=7, column=2)

        ttk.Separator(frame).grid(row=8, column=0, columnspan=3, sticky="ew", pady=18)
        ttk.Button(frame, text="签发设备绑定许可证", command=self._issue).grid(
            row=9, column=0, columnspan=3, sticky="ew", ipady=8
        )
        ttk.Label(frame, textvariable=self.status, wraplength=650, foreground="#375a7f").grid(
            row=10, column=0, columnspan=3, sticky="w", pady=(16, 0)
        )
        ttk.Label(
            frame,
            text="安全提示：本工具、加密私钥和口令仅保留在供应商离线电脑，严禁放入客户交付包。",
            wraplength=650,
            foreground="#8a3b12",
        ).grid(row=11, column=0, columnspan=3, sticky="w", pady=(12, 0))
        password_entry.focus_set()

    def _choose_key(self) -> None:
        selected = filedialog.askopenfilename(title="选择加密 Ed25519 私钥", filetypes=[("PEM 私钥", "*.pem"), ("所有文件", "*")])
        if selected:
            self.private_key.set(selected)

    def _choose_output(self) -> None:
        selected = filedialog.askdirectory(title="选择许可证输出目录")
        if selected:
            self.output_dir.set(selected)

    def _paste_machine_code(self) -> None:
        try:
            self.machine_code.set(self.clipboard_get().strip())
        except tk.TclError:
            messagebox.showwarning("剪贴板为空", "未读取到设备码。")

    def _issue(self) -> None:
        password = self.password.get()
        if not password:
            messagebox.showerror("缺少口令", "请输入加密私钥口令。")
            return
        customer = self.customer.get().strip()
        safe_customer = re.sub(r"[^A-Za-z0-9._-]+", "-", customer).strip("-._") or "customer"
        timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        output = Path(self.output_dir.get()).expanduser() / f"{safe_customer}-{self.months.get()}m-{timestamp}.autosec"
        args = argparse.Namespace(
            private_key=Path(self.private_key.get()).expanduser(),
            customer=customer,
            machine_code=self.machine_code.get().strip(),
            months=int(self.months.get()),
            days=None,
            expires_at=None,
            not_before=None,
            license_id=None,
            edition=self.edition.get(),
            features=",".join(sorted(ALL_FEATURES)),
            key_id="prod-2026-01",
            output=output,
        )
        try:
            issue(args, password=password.encode("utf-8"))
        except (OSError, ValueError, TypeError, SystemExit) as exc:
            self.password.set("")
            messagebox.showerror("签发失败", str(exc))
            return
        self.password.set("")
        self.status.set(f"签发成功：{output}")
        self.clipboard_clear()
        self.clipboard_append(str(output))
        messagebox.showinfo("签发成功", f"许可证已生成：\n{output}\n\n文件路径已复制到剪贴板。")


def main() -> int:
    LicenseIssuerApp().mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
