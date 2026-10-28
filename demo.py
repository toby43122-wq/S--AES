# -*- coding: utf-8 -*-
"""
演示脚本：把教科书附录 D 的例题一步一步算给你看
================================================

运行：
    python demo.py

输出内容：
    1. 密钥扩展的每一步（含 g 函数拆解）
    2. 加密流程的每一轮中间状态（半字节 + 二进制对照）
    3. 解密流程的每一轮中间状态
    4. ECB 与 CBC 的对比（同样两块明文，看密文有没有“重复”）
"""

from saes import (decrypt_block_trace, encrypt_block, encrypt_block_trace, expand_key,
                  expand_key_words, hex16, nibbles, rot_nib, sub_nib, g_function)
from modes import (decrypt_block_multi, decrypt_data, encrypt_block_multi,
                   encrypt_data)


def bin4(v):
    return format(v, "04b")


def show_state(v):
    """把 16 bit 状态画成 2×2 矩阵：列优先排列。"""
    n = nibbles(v)
    return ("    [ %s  %s ]   %s %s\n"
            "    [ %s  %s ]   %s %s" % (
                hex16(n[0], 1), hex16(n[1], 1), bin4(n[0]), bin4(n[1]),
                hex16(n[2], 1), hex16(n[3], 1), bin4(n[2]), bin4(n[3])))


def title(text):
    print("\n" + "=" * 68)
    print("  " + text)
    print("=" * 68)


def section(text):
    print("\n--- %s " % text + "-" * max(0, 60 - len(text)))


def demo_key_expansion(key):
    section("一、密钥扩展（主密钥 %s）" % hex16(key))
    w = expand_key_words(key)
    k0, k1, k2 = expand_key(key)
    print("  w0 = %s      w1 = %s" % (hex16(w[0], 2), hex16(w[1], 2)))
    print("       w1 = %s" % hex16(w[1], 2))
    print("  RotNib(w1)      = %s" % hex16(rot_nib(w[1]), 2))
    print("  SubNib(·)       = %s" % hex16(sub_nib(rot_nib(w[1])), 2))
    print("  g(w1) ^ RCON1   = %s   (RCON1 = 80)"
          % hex16(g_function(w[1], 0x80), 2))
    print("  w2 = w0 ^ g(w1) = %s" % hex16(w[2], 2))
    print("  w3 = w2 ^ w1    = %s" % hex16(w[3], 2))
    print("  g(w3) ^ RCON2   = %s   (RCON2 = 30)"
          % hex16(g_function(w[3], 0x30), 2))
    print("  w4 = w2 ^ g(w3) = %s" % hex16(w[4], 2))
    print("  w5 = w4 ^ w3    = %s" % hex16(w[5], 2))
    print("\n  轮密钥：K0 = w0w1 = %s" % hex16(k0))
    print("          K1 = w2w3 = %s" % hex16(k1))
    print("          K2 = w4w5 = %s" % hex16(k2))
    return k0, k1, k2


def demo_encrypt(pt, key):
    section("二、加密（明文 %s，密钥 %s）" % (hex16(pt), hex16(key)))
    ct, steps, w = encrypt_block_trace(pt, key)
    print("  初始明文\n" + show_state(pt))
    for label, value in steps:
        print("\n  %-28s -> %s" % (label, hex16(value)))
        print(show_state(value))
    print("\n  最终密文 = %s" % hex16(ct))
    return ct


def demo_decrypt(ct, key):
    section("三、解密（密文 %s，密钥 %s）" % (hex16(ct), hex16(key)))
    pt, steps = decrypt_block_trace(ct, key)
    for label, value in steps:
        print("  %-30s -> %s" % (label, hex16(value)))
    print("\n  还原明文 = %s" % hex16(pt))
    return pt


def demo_modes():
    section("四、ECB 与 CBC 对比（两块完全相同的明文）")
    key = 0x2D55
    data = bytes([0x6B, 0xA3, 0x6B, 0xA3, 0x00, 0x11])

    ecb = encrypt_data(data, [key], "ecb")
    cbc = encrypt_data(data, [key], "cbc", 0x1234)
    print("  明文(hex) : %s" % data.hex().upper())
    print("  ECB 密文  : %s   <- 前两块相同，泄露了“明文重复”" % ecb.hex().upper())
    print("  CBC 密文  : %s   <- 前两块不同，链式扩散打散了重复" % cbc.hex().upper())
    print("  CBC 解密  : %s" % decrypt_data(cbc, [key], "cbc", 0x1234).hex().upper())

    section("五、多重加密（2-S-AES / 3-S-AES）")
    k1, k2, k3 = 0x2D55, 0xA1B2, 0x0F0F
    pt = 0x6BA3
    print("  单重 : %s" % hex16(encrypt_block(pt, k1)))
    c2 = encrypt_block_multi(pt, [k1, k2])
    c3 = encrypt_block_multi(pt, [k1, k2, k3])
    print("  双重 : %s  (解密回 %s)" % (hex16(c2), hex16(decrypt_block_multi(c2, [k1, k2]))))
    print("  三重 : %s  (解密回 %s)" % (hex16(c3), hex16(decrypt_block_multi(c3, [k1, k2, k3]))))


def main():
    title("S-AES 算法演示（教科书附录 D 例题）")
    pt, key = 0x6BA3, 0x2D55
    demo_key_expansion(key)
    ct = demo_encrypt(pt, key)
    demo_decrypt(ct, key)
    demo_modes()
    title("完成：加密 6BA3 -> %s，与教科书答案 3C3B %s"
          % (hex16(ct), "一致" if ct == 0x3C3B else "不一致（请检查实现）"))


if __name__ == "__main__":
    main()
