# -*- coding: utf-8 -*-
"""
S-AES 图形界面（覆盖作业的 5 个关卡）
====================================

运行：
    python gui.py

依赖：Python 3.8+ 自带的 tkinter（Windows 官方安装包默认包含，无需 pip 安装）。

界面分为 5 个页签，与作业要求一一对应：
    第 1 关  基本测试：16 bit 明文 + 16 bit 密钥 -> 16 bit 密文，并显示每轮中间状态
    第 2 关  交叉测试：导出/校验协议向量，验证与其它小组的实现是否一致
    第 3 关  ASCII 字符串：任意长度 ASCII 文本加解密（分组 2 字节）
    第 4 关  多重加密：双重（32 bit）、三重（32/48 bit）、中间相遇攻击
    第 5 关  CBC 工作模式：长明文、随机 IV、密文篡改实验

设计说明：
    界面只负责“取值 / 显示 / 提示错误”，所有密码学运算都在 saes.py、modes.py、
    attack.py 里完成。这样换语言重写界面时，算法层可以原样复用。
"""

import json
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from attack import double_encrypt, meet_in_the_middle
from modes import (ascii_preview, decrypt_block_multi, decrypt_data,
                   encrypt_block_multi, encrypt_data, flip_bit, hex16,
                   join_key32, parse_key_text, random_iv, split_blocks)
from saes import decrypt_block_trace, encrypt_block_trace, expand_key
from vectors import build_spec, load, verify_spec

APP_TITLE = "S-AES 算法实现 · 信息安全导论 作业2"
FONT_UI = "Microsoft YaHei UI"
FONT_MONO = "Consolas"
HEX_CHARS = set("0123456789abcdefABCDEF")


# ---------------------------------------------------------------------------
# 通用小工具
# ---------------------------------------------------------------------------

def parse_hex(text, name="数值", max_bits=16):
    """解析界面上的十六进制输入，长度和字符都要合法。"""
    clean = text.strip().replace("0x", "").replace("0X", "")
    if not clean:
        raise ValueError("%s不能为空" % name)
    if any(char not in HEX_CHARS for char in clean):
        raise ValueError("%s 只能包含 0-9、A-F，例如 2D55" % name)
    if max_bits and len(clean) > max_bits // 4:
        raise ValueError("%s 最多 %d 位十六进制（%d bit）" % (name, max_bits // 4, max_bits))
    return int(clean, 16)


def set_text(widget, content):
    """写入只读文本框。"""
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", content)
    widget.configure(state="disabled")


def get_text(widget):
    return widget.get("1.0", "end").strip()


def clear_tree(tree):
    for item in tree.get_children():
        tree.delete(item)


# ---------------------------------------------------------------------------
# 主窗口
# ---------------------------------------------------------------------------

class SAESApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1040x780")
        self.minsize(960, 700)

        self._init_style()
        self._build_header()

        # 状态栏先占住底部，避免内容较高的页签把它挤掉
        self.status = ttk.Label(
            self, text="就绪：本程序实现 S-AES（教科书附录 D），明文/密文与密钥均为十六进制",
            style="Status.TLabel", anchor="w")
        self.status.pack(fill="x", side="bottom", padx=14, pady=6)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=14, pady=(6, 0))

        self._build_tab_basic()
        self._build_tab_cross()
        self._build_tab_ascii()
        self._build_tab_multi()
        self._build_tab_cbc()

        self._on_block_encrypt()   # 首屏直接展示教材例题

    # ---------------- 外观 ----------------

    def _init_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        base = "#f5f7fa"
        card = "#ffffff"
        line = "#e3e8ef"

        self.configure(background=base)
        style.configure(".", font=(FONT_UI, 10), background=card, foreground="#1f2937")
        style.configure("TFrame", background=card)
        style.configure("TLabel", background=card)
        style.configure("TLabelframe", background=card)
        style.configure("TLabelframe.Label", background=card)

        style.configure("TNotebook", background=base, borderwidth=0)
        style.configure("TNotebook.Tab", padding=(18, 9), font=(FONT_UI, 10),
                        background="#e9eef7", foreground="#41506b", borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", card), ("active", "#f0f4fc")],
                  foreground=[("selected", "#1f2937")])

        style.configure("Title.TLabel", font=(FONT_UI, 15, "bold"), background=card)
        style.configure("Sub.TLabel", font=(FONT_UI, 9), foreground="#5b6472", background=card)
        style.configure("Hint.TLabel", font=(FONT_UI, 9), foreground="#6b7280", background=card)
        style.configure("Section.TLabel", font=(FONT_UI, 11, "bold"),
                        foreground="#1f2937", background=card)
        style.configure("Result.TLabel", font=(FONT_MONO, 12, "bold"),
                        foreground="#0f7b4f", background=card)
        style.configure("Status.TLabel", font=(FONT_UI, 9), foreground="#5b6472", background=base)

        style.configure("Accent.TButton", font=(FONT_UI, 10, "bold"),
                        background="#2f6fed", foreground="white", borderwidth=0)
        style.map("Accent.TButton",
                  background=[("active", "#2560d8"), ("disabled", "#9db8ee")])
        style.configure("TButton", padding=(12, 6))

        style.configure("TEntry", fieldbackground="#fbfcfe", bordercolor=line)
        style.configure("TSpinbox", fieldbackground="#fbfcfe")
        style.configure("Treeview", rowheight=24, font=(FONT_MONO, 9),
                        background=card, fieldbackground=card)
        style.configure("Treeview.Heading", font=(FONT_UI, 9, "bold"),
                        background="#f2f5fa", foreground="#41506b")

    def _build_header(self):
        header = ttk.Frame(self, padding=(16, 14, 16, 6))
        header.pack(fill="x")
        ttk.Label(header, text="S-AES 简化加密标准 · 算法实现", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header,
                  text="16 bit 分组 / 16 bit 密钥 / 2 轮 · 密钥扩展 + 加密 + 解密 + 多重加密 + CBC",
                  style="Sub.TLabel").pack(anchor="w", pady=(4, 0))

    def _status(self, message):
        self.status.configure(text=message)

    def _error(self, error):
        messagebox.showerror("出错了", str(error))
        self._status("操作失败：%s" % error)

    # ---------------- 第 1 关 ----------------

    def _build_tab_basic(self):
        tab = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(tab, text="第1关 基本测试")

        ttk.Label(tab, text="16 bit 明文 + 16 bit 密钥 → 16 bit 密文，并显示每一轮的中间状态",
                  style="Hint.TLabel").pack(anchor="w", pady=(0, 12))

        row = ttk.Frame(tab)
        row.pack(fill="x")
        self.e_key1 = self._field(row, "密钥（16 bit）", "2D55", 0)
        self.e_plain1 = self._field(row, "明文（16 bit）", "6BA3", 1)
        self.e_cipher1 = self._field(row, "密文（16 bit）", "3C3B", 2)

        buttons = ttk.Frame(tab)
        buttons.pack(fill="x", pady=12)
        ttk.Button(buttons, text="加密 →", style="Accent.TButton",
                   command=self._on_block_encrypt).pack(side="left")
        ttk.Button(buttons, text="← 解密", command=self._on_block_decrypt).pack(side="left", padx=8)
        ttk.Button(buttons, text="恢复教材例题", command=self._on_reset_example).pack(side="left")

        self.lbl_round_keys = ttk.Label(tab, text="", style="Result.TLabel")
        self.lbl_round_keys.pack(anchor="w", pady=(0, 6))

        columns = ("step", "hex", "bin")
        self.tree_steps = ttk.Treeview(tab, columns=columns, show="headings", height=9)
        for key, title, width in (("step", "步骤", 300), ("hex", "状态（十六进制）", 140),
                                  ("bin", "状态（二进制）", 300)):
            self.tree_steps.heading(key, text=title)
            self.tree_steps.column(key, width=width, anchor="w")
        self.tree_steps.pack(fill="both", expand=True)

    def _field(self, parent, label, default, column):
        holder = ttk.Frame(parent)
        holder.grid(row=0, column=column, sticky="ew", padx=(0, 14))
        parent.columnconfigure(column, weight=1)
        ttk.Label(holder, text=label, style="Hint.TLabel").pack(anchor="w")
        entry = ttk.Entry(holder, font=(FONT_MONO, 12))
        entry.insert(0, default)
        entry.pack(fill="x", pady=(4, 0))
        return entry

    def _on_block_encrypt(self):
        try:
            key = parse_hex(self.e_key1.get(), "密钥")
            plaintext = parse_hex(self.e_plain1.get(), "明文")
        except ValueError as error:
            self._error(error)
            return

        cipher = encrypt_block_multi(plaintext, [key])
        self.e_cipher1.delete(0, "end")
        self.e_cipher1.insert(0, hex16(cipher))
        self._refresh_steps(plaintext, key)
        self._status("第1关：%s 加密为 %s（密钥 %s）"
                     % (hex16(plaintext), hex16(cipher), hex16(key)))

    def _on_block_decrypt(self):
        try:
            key = parse_hex(self.e_key1.get(), "密钥")
            cipher = parse_hex(self.e_cipher1.get(), "密文")
        except ValueError as error:
            self._error(error)
            return
        plaintext = decrypt_block_multi(cipher, [key])
        self.e_plain1.delete(0, "end")
        self.e_plain1.insert(0, hex16(plaintext))
        self._refresh_steps(plaintext, key)
        self._status("第1关：%s 解密为 %s" % (hex16(cipher), hex16(plaintext)))

    def _on_reset_example(self):
        self.e_key1.delete(0, "end")
        self.e_key1.insert(0, "2D55")
        self.e_plain1.delete(0, "end")
        self.e_plain1.insert(0, "6BA3")
        self._on_block_encrypt()
        self._status("第1关：已恢复教科书附录 D 的例题（6BA3 + 2D55 = 3C3B）")

    def _refresh_steps(self, plaintext, key):
        _, steps, _ = encrypt_block_trace(plaintext, key)
        keys = expand_key(key)
        self.lbl_round_keys.configure(
            text="轮密钥  K0=%s   K1=%s   K2=%s"
                 % (hex16(keys[0]), hex16(keys[1]), hex16(keys[2])))

        clear_tree(self.tree_steps)
        self.tree_steps.insert("", "end", values=("初始明文", hex16(plaintext),
                                                  format(plaintext, "016b")))
        for label, state in steps:
            self.tree_steps.insert("", "end",
                                   values=(label, hex16(state), format(state, "016b")))

    # ---------------- 第 2 关 ----------------

    def _build_tab_cross(self):
        tab = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(tab, text="第2关 交叉测试")

        ttk.Label(tab, text="交叉测试：另一个小组用相同密钥加密同一明文，结果必须与这里完全一致",
                  style="Hint.TLabel").pack(anchor="w")
        ttk.Label(tab, text="做法：导出我方向量交给对方，或加载对方导出的向量逐条校验。",
                  style="Hint.TLabel").pack(anchor="w", pady=(2, 12))

        buttons = ttk.Frame(tab)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="导出我方测试向量…", style="Accent.TButton",
                   command=self._on_export_vectors).pack(side="left")
        ttk.Button(buttons, text="加载对方向量并校验…",
                   command=self._on_verify_vectors).pack(side="left", padx=8)

        self.lbl_cross_summary = ttk.Label(tab, text="尚未校验", style="Section.TLabel")
        self.lbl_cross_summary.pack(anchor="w", pady=(14, 6))

        columns = ("id", "level", "desc", "result", "detail")
        self.tree_cross = ttk.Treeview(tab, columns=columns, show="headings", height=11)
        for key, title, width in (("id", "编号", 55), ("level", "关卡", 55),
                                  ("desc", "说明", 430), ("result", "结果", 70),
                                  ("detail", "明细", 300)):
            self.tree_cross.heading(key, text=title)
            self.tree_cross.column(key, width=width, anchor="w")
        self.tree_cross.pack(fill="both", expand=True)

    def _on_export_vectors(self):
        path = filedialog.asksaveasfilename(
            title="导出的测试向量", defaultextension=".json",
            initialfile="s-aes-vectors.json",
            filetypes=[("JSON 文件", "*.json")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as file:
                json.dump(build_spec(), file, ensure_ascii=False, indent=2)
        except OSError as error:
            self._error(error)
            return
        self._status("第2关：已导出 %d 条用例到 %s" % (len(build_spec()["cases"]), path))

    def _on_verify_vectors(self):
        path = filedialog.askopenfilename(title="选择对方的向量文件",
                                          filetypes=[("JSON 文件", "*.json")])
        if not path:
            return
        try:
            spec = load(path)
        except (OSError, ValueError) as error:
            self._error(error)
            return
        self._verify_and_show(spec)

    def _verify_and_show(self, spec):
        """校验协议文档并把结果填进表格（与文件选择解耦，便于自动化测试）。"""
        try:
            results, passed, total = verify_spec(spec)
        except (KeyError, ValueError) as error:
            self._error(error)
            return

        clear_tree(self.tree_cross)
        for item in results:
            ok = item["ok_encrypt"] and item["ok_decrypt"]
            detail = "一致" if ok else "加密期望 %s，实得 %s" % (item["expected"], item["got"])
            self.tree_cross.insert("", "end",
                                   values=(item["id"], item["level"], item["desc"],
                                           "PASS" if ok else "FAIL", detail))

        if passed == total:
            self.lbl_cross_summary.configure(text="全部通过：%d / %d" % (passed, total))
            self._status("第2关：交叉测试 %d / %d 通过，与对方实现完全一致" % (passed, total))
        else:
            self.lbl_cross_summary.configure(text="存在问题：%d / %d" % (passed, total))
            self._status("第2关：有 %d 条用例不一致，先确认密钥和填充规则" % (total - passed))

    # ---------------- 第 3 关 ----------------

    def _build_tab_ascii(self):
        tab = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(tab, text="第3关 ASCII 字符串")

        ttk.Label(tab, text="第 3 关：输入可以是 ASCII 字符串（按 2 字节分组），输出也是字符串（通常是乱码）",
                  style="Hint.TLabel").pack(anchor="w", pady=(0, 10))

        top = ttk.Frame(tab)
        top.pack(fill="x")
        ttk.Label(top, text="密钥（4 位十六进制）", style="Hint.TLabel").grid(row=0, column=0, sticky="w")
        self.e_key3 = ttk.Entry(top, font=(FONT_MONO, 12), width=14)
        self.e_key3.insert(0, "2D55")
        self.e_key3.grid(row=1, column=0, sticky="w", pady=(4, 0))

        self.var_ascii_input = tk.StringVar(value="text")
        ttk.Radiobutton(top, text="输入是 ASCII 原文", value="text",
                        variable=self.var_ascii_input).grid(row=1, column=1, padx=(20, 6), sticky="w")
        ttk.Radiobutton(top, text="输入是十六进制密文", value="hex",
                        variable=self.var_ascii_input).grid(row=1, column=2, padx=(6, 0), sticky="w")

        ttk.Label(tab, text="输入", style="Section.TLabel").pack(anchor="w", pady=(14, 4))
        self.txt_ascii_in = tk.Text(tab, height=5, font=(FONT_MONO, 11), wrap="word",
                                    relief="solid", borderwidth=1)
        self.txt_ascii_in.insert("1.0", "Hello, S-AES!")
        self.txt_ascii_in.pack(fill="x")

        buttons = ttk.Frame(tab)
        buttons.pack(fill="x", pady=10)
        ttk.Button(buttons, text="加密", style="Accent.TButton",
                   command=self._on_ascii_encrypt).pack(side="left")
        ttk.Button(buttons, text="解密", command=self._on_ascii_decrypt).pack(side="left", padx=8)
        ttk.Button(buttons, text="清空", command=lambda: self.txt_ascii_in.delete("1.0", "end")).pack(side="left")

        ttk.Label(tab, text="输出", style="Section.TLabel").pack(anchor="w", pady=(4, 4))
        self.txt_ascii_out = tk.Text(tab, height=9, font=(FONT_MONO, 10), wrap="word",
                                     relief="solid", borderwidth=1, background="#fbfcfe")
        self.txt_ascii_out.configure(state="disabled")
        self.txt_ascii_out.pack(fill="both", expand=True)

    def _on_ascii_encrypt(self):
        try:
            key = parse_hex(self.e_key3.get(), "密钥")
            raw = get_text(self.txt_ascii_in).encode("ascii")
            if not raw:
                raise ValueError("请输入非空的 ASCII 文本")
        except UnicodeEncodeError:
            self._error("第 3 关只接受 ASCII 字符（0x00~0x7F）；中文请用 UTF-8 模式或第 5 关")
            return
        except ValueError as error:
            self._error(error)
            return

        cipher = encrypt_data(raw, [key])
        lines = [
            "明文长度    : %d 字节（%d 个分组，已补 PKCS#7 填充）"
            % (len(raw), (len(raw) + 1) // 2),
            "密文（ASCII）: %s" % ascii_preview(cipher),
            "密文（HEX）  : %s" % cipher.hex().upper(),
            "密文长度    : %d 字节" % len(cipher),
            "",
            "说明：密文按 latin-1 还原成字符时几乎必然是乱码（·表示不可打印字符），",
            "      但可以原样复制回输入框，勾选“输入是十六进制密文”后解密。",
        ]
        set_text(self.txt_ascii_out, "\n".join(lines))
        self._status("第3关：%d 字节 ASCII 文本加密为 %d 字节密文" % (len(raw), len(cipher)))

    def _on_ascii_decrypt(self):
        try:
            key = parse_hex(self.e_key3.get(), "密钥")
            text = get_text(self.txt_ascii_in)
            data = bytes.fromhex(text) if self.var_ascii_input.get() == "hex" \
                else text.encode("latin-1")
        except ValueError as error:
            self._error("密文格式不对：%s" % error)
            return

        try:
            plain = decrypt_data(data, [key])
        except ValueError as error:
            self._error(error)
            return

        try:
            readable = plain.decode("ascii")
        except UnicodeDecodeError:
            readable = ascii_preview(plain) + "   （含非 ASCII 字节，可能密钥不同）"

        set_text(self.txt_ascii_out,
                 "解密结果（ASCII）: %s\n解密结果（HEX）  : %s\n长度            : %d 字节"
                 % (readable, plain.hex().upper(), len(plain)))
        self._status("第3关：解密得到 %d 字节明文" % len(plain))

    # ---------------- 第 4 关 ----------------

    def _build_tab_multi(self):
        tab = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(tab, text="第4关 多重加密")

        ttk.Label(tab, text="第 4 关：双重加密用 32 bit 密钥（K1+K2）；三重加密可选 32 bit（K1K2K1）或 48 bit（K1K2K3）",
                  style="Hint.TLabel").pack(anchor="w", pady=(0, 10))

        top = ttk.Frame(tab)
        top.pack(fill="x")
        ttk.Label(top, text="密钥（8 位或 12 位十六进制）", style="Hint.TLabel").grid(row=0, column=0, sticky="w")
        self.e_key4 = ttk.Entry(top, font=(FONT_MONO, 12), width=20)
        self.e_key4.insert(0, "2D55A1B2")
        self.e_key4.grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.e_key4.bind("<KeyRelease>", lambda event: self._refresh_key_split())

        self.var_multi_mode = tk.StringVar(value="double")
        modes = ttk.Frame(top)
        modes.grid(row=1, column=1, padx=(24, 0), sticky="w")
        ttk.Radiobutton(modes, text="双重 32 bit", value="double",
                        variable=self.var_multi_mode, command=self._refresh_key_split).pack(anchor="w")
        ttk.Radiobutton(modes, text="三重 32 bit（K1K2K1）", value="triple32",
                        variable=self.var_multi_mode, command=self._refresh_key_split).pack(anchor="w")
        ttk.Radiobutton(modes, text="三重 48 bit（K1K2K3）", value="triple48",
                        variable=self.var_multi_mode, command=self._refresh_key_split).pack(anchor="w")

        self.lbl_key_split = ttk.Label(tab, text="", style="Hint.TLabel")
        self.lbl_key_split.pack(anchor="w", pady=(6, 4))

        row = ttk.Frame(tab)
        row.pack(fill="x")
        self.e_plain4 = self._field(row, "明文（16 bit）", "6BA3", 0)
        self.e_cipher4 = self._field(row, "密文（16 bit）", "", 1)

        buttons = ttk.Frame(tab)
        buttons.pack(fill="x", pady=6)
        ttk.Button(buttons, text="加密 →", style="Accent.TButton",
                   command=self._on_multi_encrypt).pack(side="left")
        ttk.Button(buttons, text="← 解密", command=self._on_multi_decrypt).pack(side="left", padx=8)

        ttk.Separator(tab, orient="horizontal").pack(fill="x", pady=8)

        ttk.Label(tab, text="4.2 中间相遇攻击", style="Section.TLabel").pack(anchor="w")
        ttk.Label(tab, text="输入一组或多组“明文:密文”（每行一组）。单组会有大量误报，建议 3 组。",
                  style="Hint.TLabel").pack(anchor="w", pady=(2, 6))

        pair_area = ttk.Frame(tab)
        pair_area.pack(fill="x")
        self.txt_pairs = tk.Text(pair_area, height=3, font=(FONT_MONO, 10), width=40,
                                 relief="solid", borderwidth=1)
        self.txt_pairs.pack(side="left", fill="both", expand=True)
        self.txt_pairs.insert("1.0", "6BA3:887F\n1234:30D4\nABCD:1198")

        side = ttk.Frame(pair_area)
        side.pack(side="left", padx=(10, 0), fill="y")
        ttk.Button(side, text="按当前密钥生成示例", command=self._on_fill_pairs).pack(fill="x")
        self.btn_mitm = ttk.Button(side, text="执行中间相遇攻击", style="Accent.TButton",
                                   command=self._on_mitm)
        self.btn_mitm.pack(fill="x", pady=8)

        self.lbl_mitm = ttk.Label(tab, text="等待执行", style="Hint.TLabel", justify="left")
        self.lbl_mitm.pack(anchor="w", pady=(4, 0), fill="x")

        self._refresh_key_split()

    def _current_multi_keys(self):
        """按当前模式解析密钥，返回 (keys, 模式名)。"""
        keys = parse_key_text(self.e_key4.get())
        mode = self.var_multi_mode.get()

        if mode == "double":
            if len(keys) != 2:
                raise ValueError("双重加密需要 8 位密钥（K1+K2），例如 2D55A1B2")
            return keys, "双重加密"
        if mode == "triple32":
            if len(keys) != 2:
                raise ValueError("三重加密（32 bit）需要 8 位密钥，例如 2D55A1B2")
            return [keys[0], keys[1], keys[0]], "三重加密（K1K2K1）"
        if len(keys) != 3:
            raise ValueError("三重加密（48 bit）需要 12 位密钥，例如 2D55A1B20F0F")
        return keys, "三重加密（K1K2K3）"

    def _refresh_key_split(self):
        try:
            keys, mode = self._current_multi_keys()
        except ValueError as error:
            self.lbl_key_split.configure(text="密钥格式：%s" % error)
            return
        parts = "  ".join("K%d=%s" % (index + 1, hex16(key)) for index, key in enumerate(keys))
        if len(keys) == 3 and keys[0] == keys[2]:
            parts += "（K3 = K1，32 bit 密钥）"
        self.lbl_key_split.configure(text="%s：%s" % (mode, parts))

    def _on_multi_encrypt(self):
        try:
            keys, mode = self._current_multi_keys()
            plaintext = parse_hex(self.e_plain4.get(), "明文")
        except ValueError as error:
            self._error(error)
            return
        cipher = encrypt_block_multi(plaintext, keys)
        self.e_cipher4.delete(0, "end")
        self.e_cipher4.insert(0, hex16(cipher))
        self._status("第4关：%s，%s 加密为 %s" % (mode, hex16(plaintext), hex16(cipher)))

    def _on_multi_decrypt(self):
        try:
            keys, mode = self._current_multi_keys()
            cipher = parse_hex(self.e_cipher4.get(), "密文")
        except ValueError as error:
            self._error(error)
            return
        plaintext = decrypt_block_multi(cipher, keys)
        self.e_plain4.delete(0, "end")
        self.e_plain4.insert(0, hex16(plaintext))
        self._status("第4关：%s，%s 解密为 %s" % (mode, hex16(cipher), hex16(plaintext)))

    def _on_fill_pairs(self):
        try:
            keys, _ = self._current_multi_keys()
        except ValueError as error:
            self._error(error)
            return
        if len(keys) < 2:
            self._error("中间相遇攻击针对双重加密，请选“双重 32 bit”并填 8 位密钥")
            return
        lines = []
        for sample in (0x6BA3, 0x1234, 0xABCD):
            lines.append("%s:%s" % (hex16(sample), hex16(double_encrypt(sample, keys[0], keys[1]))))
        self.txt_pairs.delete("1.0", "end")
        self.txt_pairs.insert("1.0", "\n".join(lines))
        self._status("第4关：已按当前密钥生成 3 组明密文对")

    def _read_pairs(self):
        pairs = []
        for line in get_text(self.txt_pairs).splitlines():
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                raise ValueError("每一行写成 明文:密文，例如 6BA3:887F")
            plain_text, cipher_text = line.split(":", 1)
            pairs.append((parse_hex(plain_text, "明文"), parse_hex(cipher_text, "密文")))
        if not pairs:
            raise ValueError("请至少输入一组明密文对")
        return pairs

    def _on_mitm(self):
        try:
            pairs = self._read_pairs()
        except ValueError as error:
            self._error(error)
            return

        self.btn_mitm.configure(state="disabled")
        self.lbl_mitm.configure(text="正在扫描 2^16 个 K1 与 2^16 个 K2，约需 2~5 秒…")

        def work():
            started = time.time()
            survivors, stats = meet_in_the_middle(pairs)
            elapsed = time.time() - started
            self.after(0, lambda: self._show_mitm(survivors, stats, elapsed))

        threading.Thread(target=work, daemon=True).start()

    def _show_mitm(self, survivors, stats, elapsed):
        self.btn_mitm.configure(state="normal")
        if not survivors:
            self.lbl_mitm.configure(text="没有找到匹配密钥，请检查明密文对是否属于同一密钥")
            self._status("第4关：攻击失败，未找到候选密钥")
            return

        lines = []
        if len(survivors) == 1:
            key1, key2 = survivors[0]
            lines.append("恢复出的密钥 Key = %s（K1=%s，K2=%s）"
                         % (hex16(join_key32(key1, key2), 8), hex16(key1), hex16(key2)))
        else:
            lines.append("候选 %d 组（不唯一），例如：" % len(survivors))
            for key1, key2 in survivors[:5]:
                lines.append("    K1=%s K2=%s → Key=%s"
                             % (hex16(key1), hex16(key2), hex16(join_key32(key1, key2), 8)))
            lines.append("    提示：再补充明密文对（共 3 组）即可唯一确定。")
        lines.append("扫描 2^16 × 2^16 空间，首次命中 %d 组，过滤后剩 %d 组，耗时 %.2f 秒"
                     % (stats["first_hits"], stats["survivors"], elapsed))
        self.lbl_mitm.configure(text="\n".join(lines))
        self._status("第4关：中间相遇攻击完成，用时 %.2f 秒" % elapsed)

    # ---------------- 第 5 关 ----------------

    def _build_tab_cbc(self):
        tab = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(tab, text="第5关 CBC 工作模式")

        ttk.Label(tab, text="第 5 关：CBC 链式加密长明文；IV 随机生成并由双方共享；可与篡改实验对照",
                  style="Hint.TLabel").pack(anchor="w", pady=(0, 6))

        params = ttk.Frame(tab)
        params.pack(fill="x")
        ttk.Label(params, text="密钥", style="Hint.TLabel").grid(row=0, column=0, sticky="w")
        self.e_key5 = ttk.Entry(params, font=(FONT_MONO, 12), width=12)
        self.e_key5.insert(0, "2D55")
        self.e_key5.grid(row=1, column=0, sticky="w")

        ttk.Label(params, text="初始向量 IV", style="Hint.TLabel").grid(row=0, column=1, padx=(20, 0), sticky="w")
        self.e_iv5 = ttk.Entry(params, font=(FONT_MONO, 12), width=12)
        self.e_iv5.insert(0, hex16(random_iv()))
        self.e_iv5.grid(row=1, column=1, padx=(20, 0), sticky="w")
        ttk.Button(params, text="随机生成 IV", command=self._on_random_iv).grid(
            row=1, column=2, padx=(8, 0), sticky="w")

        ttk.Label(tab, text="明文（任意长度，按 2 字节分组）", style="Section.TLabel").pack(
            anchor="w", pady=(8, 2))
        self.txt_plain5 = tk.Text(tab, height=2, font=(FONT_MONO, 10), wrap="word",
                                  relief="solid", borderwidth=1)
        self.txt_plain5.insert("1.0", "S-AES CBC 模式演示：这是一段较长的明文，需要分成多个分组加密。")
        self.txt_plain5.pack(fill="x")

        buttons = ttk.Frame(tab)
        buttons.pack(fill="x", pady=6)
        ttk.Button(buttons, text="CBC 加密", style="Accent.TButton",
                   command=self._on_cbc_encrypt).pack(side="left")
        ttk.Button(buttons, text="CBC 解密", command=self._on_cbc_decrypt).pack(side="left", padx=8)

        ttk.Label(tab, text="密文（十六进制，不含 IV）", style="Section.TLabel").pack(anchor="w", pady=(2, 4))
        self.txt_cipher5 = tk.Text(tab, height=2, font=(FONT_MONO, 10), wrap="char",
                                   relief="solid", borderwidth=1)
        self.txt_cipher5.pack(fill="x")

        ttk.Separator(tab, orient="horizontal").pack(fill="x", pady=6)

        tamper = ttk.Frame(tab)
        tamper.pack(fill="x")
        ttk.Label(tamper, text="密文篡改实验：翻转某个分组中的一位，再解密对比结果",
                  style="Section.TLabel").pack(anchor="w")

        controls = ttk.Frame(tamper)
        controls.pack(anchor="w", pady=4)
        ttk.Label(controls, text="分组序号").pack(side="left")
        self.spin_block = ttk.Spinbox(controls, from_=0, to=0, width=5)
        self.spin_block.set(0)
        self.spin_block.pack(side="left", padx=(6, 16))
        ttk.Label(controls, text="位序号（1=最高位）").pack(side="left")
        self.spin_bit = ttk.Spinbox(controls, from_=1, to=16, width=5)
        self.spin_bit.set(1)
        self.spin_bit.pack(side="left", padx=(6, 16))
        ttk.Button(controls, text="篡改并解密", command=self._on_tamper).pack(side="left")

        result_box = ttk.Frame(tab)
        result_box.pack(fill="both", expand=True, pady=(6, 0))
        scrollbar = ttk.Scrollbar(result_box, orient="vertical")
        self.txt_tamper = tk.Text(result_box, height=4, font=(FONT_MONO, 10), wrap="word",
                                  relief="solid", borderwidth=1, background="#fbfcfe",
                                  yscrollcommand=scrollbar.set)
        scrollbar.configure(command=self.txt_tamper.yview)
        self.txt_tamper.configure(state="disabled")
        self.txt_tamper.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _on_random_iv(self):
        self.e_iv5.delete(0, "end")
        self.e_iv5.insert(0, hex16(random_iv()))
        self._status("第5关：已随机生成 IV，请与对方共享（IV 不需要保密）")

    def _cbc_cipher_bytes(self):
        text = get_text(self.txt_cipher5)
        if not text:
            raise ValueError("还没有密文，请先执行 CBC 加密")
        return bytes.fromhex(text)

    def _on_cbc_encrypt(self):
        try:
            key = parse_hex(self.e_key5.get(), "密钥")
            iv = parse_hex(self.e_iv5.get(), "IV")
            plain = get_text(self.txt_plain5).encode("utf-8")
        except ValueError as error:
            self._error(error)
            return

        cipher = encrypt_data(plain, [key], "cbc", iv)
        set_editable_text(self.txt_cipher5, cipher.hex().upper())
        blocks = len(split_blocks(cipher))
        self.spin_block.configure(to=max(0, blocks - 1))
        self._status("第5关：CBC 加密完成，明文 %d 字节 → 密文 %d 字节（%d 个分组）"
                     % (len(plain), len(cipher), blocks))
        set_text(self.txt_tamper,
                 "IV = %s（请与接收方共享）\n密文分组数：%d\n可拖动“分组序号”后点击“篡改并解密”观察影响。"
                 % (hex16(iv), blocks))

    def _on_cbc_decrypt(self):
        try:
            key = parse_hex(self.e_key5.get(), "密钥")
            iv = parse_hex(self.e_iv5.get(), "IV")
            cipher = self._cbc_cipher_bytes()
            plain = decrypt_data(cipher, [key], "cbc", iv)
        except ValueError as error:
            self._error(error)
            return

        text = plain.decode("utf-8", "replace")
        set_editable_text(self.txt_plain5, text)
        self._status("第5关：CBC 解密完成，得到 %d 字节明文" % len(plain))

    def _on_tamper(self):
        try:
            key = parse_hex(self.e_key5.get(), "密钥")
            iv = parse_hex(self.e_iv5.get(), "IV")
            cipher = self._cbc_cipher_bytes()
            block_index = int(self.spin_block.get())
            bit_index = int(self.spin_bit.get())
            broken = flip_bit(cipher, block_index, bit_index)
            original = decrypt_data(cipher, [key], "cbc", iv)
        except ValueError as error:
            self._error(error)
            return

        try:
            damaged_text = decrypt_data(broken, [key], "cbc", iv).decode("utf-8", "replace")
        except ValueError as error:
            # 篡改落在最后一个分组时，填充校验可能直接拦住
            damaged_text = "解密失败：%s（说明填充校验发现了篡改）" % error

        next_block = block_index + 1 if block_index + 1 < len(split_blocks(cipher)) else None
        lines = [
            "篡改位置：第 %d 个分组（从 0 计）第 %d 位（1 = 最高位）" % (block_index, bit_index),
            "篡改前明文：%s" % original.decode("utf-8", "replace"),
            "篡改后明文：%s" % damaged_text,
            "",
            "现象：第 %d 个分组整块变成乱码；%s" % (
                block_index,
                "第 %d 个分组只翻转了对应的那一位；" % next_block if next_block is not None
                else "它是最后一个分组，后面的分组不存在；"),
            "      再往后的分组不受影响 —— 这就是 CBC 的错误传播特性。",
            "",
            "原始密文：%s" % cipher.hex().upper(),
            "篡改密文：%s" % broken.hex().upper(),
        ]
        set_text(self.txt_tamper, "\n".join(lines))
        self._status("第5关：已篡改第 %d 个分组并完成对比" % block_index)


def set_editable_text(widget, content):
    """写入可编辑文本框（用于回填明文/密文）。"""
    widget.delete("1.0", "end")
    widget.insert("1.0", content)


def main():
    app = SAESApp()
    app.mainloop()


if __name__ == "__main__":
    main()
