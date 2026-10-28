# -*- coding: utf-8 -*-
"""
S-AES 命令行工具
================

桌面界面请直接运行 `python gui.py`（需要带 tkinter 的 Python）。
本文件提供与之等价的命令行入口，方便批量测试和写测试报告。

常用命令：

    # 第 1 关：单分组加解密（16 bit）
    python main.py block -k 2D55 -p 6BA3
    python main.py block -k 2D55 -c 3C3B --dec
    python main.py block -k 2D55 -p 6BA3 --trace

    # 第 2 关：交叉测试（校验协议向量）
    python main.py interop
    python main.py interop --vectors 对方组的vectors.json

    # 第 3 关：ASCII 字符串
    python main.py enc -k 2D55 -t "Hello!" --ascii
    python main.py dec -k 2D55 -t "<密文字符串>" --ascii

    # 第 4 关：多重加密（32 bit / 48 bit 密钥）
    python main.py enc -k 2D55A1B2 --mode double -p 6BA3
    python main.py enc -k 2D55A1B2 --mode triple -p 6BA3      # K1K2K1
    python main.py enc -k 2D55A1B20F0F --mode triple -p 6BA3  # K1K2K3
    python main.py mitm --pairs "6BA3:887F"

    # 第 5 关：CBC 与密文篡改
    python main.py enc -k 2D55 --chain cbc --iv 1234 -t "hello"
    python main.py tamper -k 2D55 --chain cbc --iv 1234 -t "hello" --block 0 --bit 1

    # 其他
    python main.py key -k 2D55      # 查看密钥扩展
    python main.py test             # 跑全部单元测试
"""

import argparse
import json
import os
import sys
import time

from attack import meet_in_the_middle
from modes import (ascii_preview, decrypt_block_multi, decrypt_data,
                   encrypt_block_multi, encrypt_data, flip_bit, hex16,
                   join_key32, parse_key_text, split_blocks)
from saes import (decrypt_block, decrypt_block_trace, encrypt_block,
                  encrypt_block_trace, expand_key, expand_key_words)
from vectors import load, verify_spec


# ---------------------------------------------------------------------------
# 参数解析小工具
# ---------------------------------------------------------------------------

def parse_hex(text, name="数值"):
    """接受 '2D55'、'0x2D55'、'2d55' 等写法。"""
    try:
        return int(text.strip().replace("0x", "").replace("0X", ""), 16)
    except (TypeError, ValueError):
        raise SystemExit("参数错误：%s 必须是十六进制，例如 2D55" % name)


def collect_keys(args):
    """
    根据 --mode 收集密钥：
        single  -> 4 位十六进制
        double  -> 8 位（32 bit）或 --key2
        triple  -> 8 位（K1K2K1）或 12 位（K1K2K3），也可用 --key2/--key3
    """
    if args.mode == "single":
        return [parse_hex(args.key, "--key")]

    if args.key2:
        keys = [parse_hex(args.key, "--key"), parse_hex(args.key2, "--key2")]
        if args.mode == "triple":
            if not args.key3:
                raise SystemExit("三重加密请提供 --key3，或直接用 8/12 位的 --key")
            keys.append(parse_hex(args.key3, "--key3"))
        return keys

    try:
        keys = parse_key_text(args.key)
    except ValueError as error:
        raise SystemExit("参数错误：%s" % error)

    if args.mode == "double":
        if len(keys) != 2:
            raise SystemExit("双重加密的 --key 应为 8 位十六进制（32 bit），如 2D55A1B2")
        return keys

    # 三重加密：32 bit 密钥用 K1K2K1 结构
    if len(keys) == 2:
        keys = [keys[0], keys[1], keys[0]]
    return keys


def read_input(args):
    """把 -t / --hex / -f 统一成字节串。"""
    if args.text is not None:
        if args.ascii:
            return args.text.encode("latin-1"), "ascii"
        return args.text.encode("utf-8"), "text"
    if args.hex is not None:
        return bytes.fromhex(args.hex), "hex"
    if args.file:
        with open(args.file, "rb") as file:
            return file.read(), "file"
    raise SystemExit("请用 -t 文本 / --hex 十六进制 / -f 文件 指定输入")


def write_output(data, args, is_text):
    if args.out:
        with open(args.out, "wb") as file:
            file.write(data)
        print("已写入 %s（%d 字节）" % (os.path.abspath(args.out), len(data)))
        return
    if is_text:
        sys.stdout.buffer.write(data)
        print()
    else:
        print(data.hex().upper())


# ---------------------------------------------------------------------------
# 各子命令
# ---------------------------------------------------------------------------

def cmd_block(args):
    """
    第 1 关与第 4 关：单个 16 bit 分组的加解密。
    单重时支持 --trace 打印每一轮；双重/三重直接给出最终结果。
    """
    keys = collect_keys(args)
    single = len(keys) == 1

    if args.dec:
        value = parse_hex(args.cipher, "-c")
        if single and args.trace:
            plain, steps = decrypt_block_trace(value, keys[0])
            print("轮密钥: %s" % [hex16(k) for k in expand_key(keys[0])])
            for label, state in steps:
                print("  %-32s -> %s" % (label, hex16(state)))
            print("明文: %s" % hex16(plain))
        else:
            print(hex16(decrypt_block_multi(value, keys)))
    else:
        value = parse_hex(args.plain, "-p")
        if single and args.trace:
            cipher, steps, words = encrypt_block_trace(value, keys[0])
            print("w0..w5: %s" % [hex16(w, 2) for w in words])
            print("轮密钥: %s" % [hex16(k) for k in expand_key(keys[0])])
            for label, state in steps:
                print("  %-32s -> %s" % (label, hex16(state)))
            print("密文: %s" % hex16(cipher))
        else:
            print(hex16(encrypt_block_multi(value, keys)))


def cmd_enc(args):
    keys = collect_keys(args)
    data, _ = read_input(args)
    raw = encrypt_data(data, keys, args.chain, parse_hex(args.iv, "--iv"))

    if args.json:
        print(json.dumps({
            "algorithm": "S-AES",
            "keys": [hex16(k) for k in keys],
            "chain": args.chain,
            "iv": hex16(parse_hex(args.iv, "--iv")),
            "ciphertext": raw.hex().upper(),
            "length": len(raw),
        }, ensure_ascii=False, indent=2))
        return

    if args.ascii:
        print("ASCII: %s" % ascii_preview(raw))
        print("HEX  : %s" % raw.hex().upper())
        return
    write_output(raw, args, is_text=False)


def cmd_dec(args):
    keys = collect_keys(args)
    data, kind = read_input(args)
    if kind in ("text", "ascii") and not args.ascii:
        # 未加 --ascii 时，-t 里填的是十六进制密文
        try:
            data = bytes.fromhex(args.text)
        except ValueError:
            raise SystemExit("解密时 -t 需要填十六进制密文，或用 --hex / -f")
    try:
        plain = decrypt_data(data, keys, args.chain, parse_hex(args.iv, "--iv"))
    except ValueError as error:
        raise SystemExit("解密失败：%s" % error)

    if args.json:
        print(json.dumps({"plaintext": plain.decode("utf-8", "replace"),
                          "hex": plain.hex().upper()}, ensure_ascii=False, indent=2))
        return
    if args.ascii:
        print("明文(ASCII): %s" % ascii_preview(plain))
        return
    write_output(plain, args, is_text=True)


def cmd_key(args):
    key = parse_hex(args.key, "--key")
    words = expand_key_words(key)
    print("主密钥 : %s  (%s)" % (hex16(key), format(key, "016b")))
    print("w0..w5 : %s" % "  ".join(hex16(w, 2) for w in words))
    for index, round_key in enumerate(expand_key(key)):
        print("K%d     : %s  (%s)" % (index, hex16(round_key), format(round_key, "016b")))


def cmd_mitm(args):
    """第 4 关 4.2：中间相遇攻击"""
    pairs = []
    for item in args.pairs.split(","):
        item = item.strip()
        if not item:
            continue
        if ":" not in item:
            raise SystemExit("明密文对应写成 明文:密文，例如 6BA3:887F")
        plain_text, cipher_text = item.split(":", 1)
        pairs.append((parse_hex(plain_text, "明文"), parse_hex(cipher_text, "密文")))
    if not pairs:
        raise SystemExit("请用 --pairs 提供至少一组明密文对")

    print("已知明密文对 %d 组：" % len(pairs))
    for plain_text, cipher_text in pairs:
        print("  %s -> %s" % (hex16(plain_text), hex16(cipher_text)))

    started = time.time()
    survivors, stats = meet_in_the_middle(pairs)
    elapsed = time.time() - started

    print("\n扫描密钥空间 : 2^16 = %d" % stats["keys_scanned"])
    print("首次命中     : %d 组候选" % stats["first_hits"])
    print("过滤后剩余   : %d 组" % stats["survivors"])
    for key1, key2 in survivors[:10]:
        print("  K1 = %s  K2 = %s  =>  Key = %s"
              % (hex16(key1), hex16(key2), hex16(join_key32(key1, key2), 8)))
    if stats["survivors"] > 10:
        print("  ……（其余 %d 组略）" % (stats["survivors"] - 10))
    print("耗时         : %.2f 秒" % elapsed)

    if stats["survivors"] > 1:
        print("\n提示：候选不唯一。只有一组明密文对时，命中数约为 2^16，"
              "这是中间相遇攻击的固有特性。")
        print("      再补充 2 组明密文对（--pairs \"P1:C1,P2:C2,P3:C3\"）即可唯一确定密钥。")
    elif stats["survivors"] == 1:
        print("\n结论：密钥唯一确定。")


def cmd_tamper(args):
    """第 5 关：篡改密文后对比解密结果"""
    keys = collect_keys(args) if args.mode != "single" else [parse_hex(args.key, "--key")]
    data, _ = read_input(args)
    iv = parse_hex(args.iv, "--iv")
    cipher = encrypt_data(data, keys, args.chain, iv)

    print("明文(hex)  : %s" % data.hex().upper())
    print("密文(hex)  : %s" % cipher.hex().upper())

    broken = flip_bit(cipher, args.block, args.bit)
    print("篡改位置   : 第 %d 个分组（从 0 计），第 %d 位（从最高位计）"
          % (args.block, args.bit))
    print("篡改后密文 : %s" % broken.hex().upper())

    for label, blob in (("篡改前解密", cipher), ("篡改后解密", broken)):
        try:
            plain = decrypt_data(blob, keys, args.chain, iv)
            print("%s : %s" % (label, ascii_preview(plain) if args.ascii
                               else plain.hex().upper()))
        except ValueError as error:
            print("%s : 解密失败（%s）" % (label, error))

    print("\n密文分组明细：")
    for index, block in enumerate(split_blocks(broken)):
        print("  分组 %d: %s" % (index, block.hex().upper()))


def cmd_test(args):
    import unittest
    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, here)
    suite = unittest.TestLoader().discover(os.path.join(here, "tests"), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


def cmd_interop(args):
    """第 2 关：按协议逐条校验（默认校验仓库自带的向量）"""
    spec = load(args.vectors)
    results, passed, total = verify_spec(spec)

    print("协议版本: %s" % spec.get("version", "?"))
    for item in results:
        ok = item["ok_encrypt"] and item["ok_decrypt"]
        print("  [%s] #%s 第%s关 %s"
              % ("PASS" if ok else "FAIL", item["id"], item["level"], item["desc"]))
        if not item["ok_encrypt"]:
            print("        加密不符：期望 %s，实际 %s" % (item["expected"], item["got"]))
        if not item["ok_decrypt"]:
            print("        解密不符：期望 %s，实际 %s" % (item["expected_plain"], item["back"]))

    print("\n共 %d 条用例，通过 %d 条，失败 %d 条" % (total, passed, total - passed))
    sys.exit(0 if passed == total else 1)


# ---------------------------------------------------------------------------
# 参数定义
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="S-AES",
        description="S-AES（简化 AES）：单分组加解密、ASCII 字符串、多重加密、CBC 工作模式",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="图形界面请运行：python gui.py")
    sub = parser.add_subparsers(dest="cmd")

    block = sub.add_parser("block", help="第 1 关：单个 16 bit 分组加解密（也支持双重/三重）")
    block.add_argument("-k", "--key", required=True,
                       help="密钥：4 位（单重）、8 位（双重/三重 32 bit）、12 位（三重 48 bit）")
    block.add_argument("-k2", "--key2", help="密钥 2")
    block.add_argument("-k3", "--key3", help="密钥 3")
    block.add_argument("--mode", default="single", choices=["single", "double", "triple"],
                       help="单重 / 双重 / 三重，默认 single")
    group = block.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--plain", help="明文，如 6BA3")
    group.add_argument("-c", "--cipher", help="密文，如 3C3B")
    block.add_argument("--dec", action="store_true", help="解密模式")
    block.add_argument("--trace", action="store_true", help="打印每一轮的中间状态（仅单重）")
    block.set_defaults(func=cmd_block)

    for name, handler, helptext in (("enc", cmd_enc, "加密"), ("dec", cmd_dec, "解密")):
        cmd = sub.add_parser(name, help=helptext)
        cmd.add_argument("-k", "--key", required=True,
                         help="密钥：4/8/12 位十六进制（单重/双重/三重）")
        cmd.add_argument("-k2", "--key2", help="密钥 2（也可把密钥拼成 8/12 位传给 -k）")
        cmd.add_argument("-k3", "--key3", help="密钥 3（48 bit 三重加密用）")
        cmd.add_argument("--mode", default="single", choices=["single", "double", "triple"],
                         help="单重 / 双重 / 三重，默认 single")
        cmd.add_argument("--chain", default="ecb", choices=["ecb", "cbc"],
                         help="工作模式，默认 ecb")
        cmd.add_argument("--iv", default="0000", help="CBC 初始向量，默认 0000")
        cmd.add_argument("-t", "--text", help="文本输入")
        cmd.add_argument("--hex", help="十六进制输入")
        cmd.add_argument("-c", dest="hex", help="十六进制输入（同 --hex）")
        cmd.add_argument("-f", "--file", help="文件输入")
        cmd.add_argument("-o", "--out", help="输出到文件")
        cmd.add_argument("--ascii", action="store_true", help="第 3 关：按 ASCII 字符串处理")
        cmd.add_argument("--json", action="store_true", help="以 JSON 输出，便于组间对接")
        cmd.set_defaults(func=handler)

    key_cmd = sub.add_parser("key", help="查看密钥扩展")
    key_cmd.add_argument("-k", "--key", required=True)
    key_cmd.set_defaults(func=cmd_key)

    mitm = sub.add_parser("mitm", help="第 4 关 4.2：中间相遇攻击")
    mitm.add_argument("--pairs", required=True, help='明密文对，如 "6BA3:887F,1234:DC1B"')
    mitm.set_defaults(func=cmd_mitm)

    tamper = sub.add_parser("tamper", help="第 5 关：篡改密文后对比解密结果")
    tamper.add_argument("-k", "--key", required=True)
    tamper.add_argument("--mode", default="single", choices=["single", "double", "triple"])
    tamper.add_argument("--chain", default="cbc", choices=["ecb", "cbc"])
    tamper.add_argument("--iv", default="0000")
    tamper.add_argument("-t", "--text")
    tamper.add_argument("--hex")
    tamper.add_argument("-f", "--file")
    tamper.add_argument("--block", type=int, default=0, help="要篡改的分组序号，从 0 开始")
    tamper.add_argument("--bit", type=int, default=1, help="分组内位序号，1~16")
    tamper.add_argument("--ascii", action="store_true")
    tamper.set_defaults(func=cmd_tamper)

    test_cmd = sub.add_parser("test", help="运行全部单元测试")
    test_cmd.set_defaults(func=cmd_test)

    interop = sub.add_parser("interop", help="第 2 关：按协议向量校验实现")
    interop.add_argument("--vectors", default="data/vectors.json")
    interop.set_defaults(func=cmd_interop)
    return parser


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()
    if not getattr(args, "func", None):
        parser.print_help()
        sys.exit(0)
    args.func(args)
