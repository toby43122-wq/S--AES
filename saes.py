# -*- coding: utf-8 -*-
"""
S-AES（Simplified AES）核心算法实现
===================================

依据：《密码学与网络安全》附录 D（Stallings, Appendix D: Simplified AES）

S-AES 与 AES 的对应关系：
    AES  : 128 bit 分组 / 128·192·256 bit 密钥 / 10·12·14 轮
    S-AES:  16 bit 分组 /        16 bit 密钥 /          2 轮

分组结构：16 bit 明文拆成 4 个半字节(nibble)，按列排成 2×2 状态矩阵
        n0 n1         s00 s10
        n2 n3   即    s01 s11
（本实现内部统一用整数表示：n0 在最高 4 位，n3 在最低 4 位）

一轮加密：半字节替换 → 行移位 → 列混淆 → 轮密钥加
第二轮没有列混淆，与 AES 的最后一轮一致。

作者：<填写你的名字>
课程：信息安全导论 · 课外作业2
"""

# ---------------------------------------------------------------------------
# 一、常量：S 盒、逆 S 盒、轮常数
# ---------------------------------------------------------------------------

# S-AES 的 4 bit S 盒（教科书附录 D 表 D.1）
SBOX = [
    0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5,
    0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7,
]

# 逆 S 盒：由 S 盒反查得到（不是另一张独立表，测试里会验证这一点）
INV_SBOX = [0] * 16
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i
del _i, _v
INV_SBOX = [0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF,
            0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE]

# 轮常数：两轮各一个，作用于 g 函数输出的高字节
RCON1 = 0x80
RCON2 = 0x30


# ---------------------------------------------------------------------------
# 二、GF(2^4) 有限域运算
# ---------------------------------------------------------------------------
# S-AES 的列混淆在 GF(2^4) 上做矩阵乘法，模多项式 x^4 + x + 1（即 0b10011）

MOD_POLY = 0b10011  # x^4 + x + 1


def gmul(a, b):
    """GF(2^4) 乘法：俄罗斯农民乘法 + 模 x^4+x+1 约简。"""
    result = 0
    for _ in range(4):
        if b & 1:
            result ^= a
        carry = a & 0x8           # 最高位为 1，左移后会溢出一个 x^4
        a = (a << 1) & 0xF
        if carry:
            a ^= 0x3              # x^4 ≡ x + 1 (mod x^4+x+1)
        b >>= 1
    return result & 0xF


def ginv(a):
    """GF(2^4) 乘法逆元（用于构造 S 盒）。0 的逆元按约定取 0。"""
    if a == 0:
        return 0
    for x in range(1, 16):
        if gmul(a, x) == 1:
            return x
    raise ValueError(f"{a} 在 GF(2^4) 中不可逆")  # 理论上不会发生


def _rotl4(x, n):
    """4 bit 循环左移。"""
    n %= 4
    return ((x << n) | (x >> (4 - n))) & 0xF


def build_sbox():
    """
    按教科书的方式“算”出 S 盒，用来验证表 D.1 不是抄错的：

        y = 逆元(x) ⊕ rotl(逆元(x), 2) ⊕ rotl(逆元(x), 3) ⊕ 0x9

    这与第 8 讲里 AES S 盒 = GF(2^8) 求逆 + 仿射变换的构造思路完全一致，
    只是规模从 8 bit 缩小到 4 bit。测试里会逐项比对，保证结果与表 D.1 相同。
    """
    box = []
    for x in range(16):
        b = ginv(x)
        # 仿射变换：b ⊕ (b<<<2) ⊕ (b<<<3) ⊕ 常数 0x9
        y = b ^ _rotl4(b, 2) ^ _rotl4(b, 3) ^ 0x9
        box.append(y)
    return box


# ---------------------------------------------------------------------------
# 三、基本工具：半字节拆分 / 合并
# ---------------------------------------------------------------------------

def nibbles(block):
    """0x6BA3 -> [0x6, 0xB, 0xA, 0x3]"""
    return [(block >> 12) & 0xF, (block >> 8) & 0xF,
            (block >> 4) & 0xF, block & 0xF]


def pack(ns):
    """[0x6, 0xB, 0xA, 0x3] -> 0x6BA3"""
    return (ns[0] << 12) | (ns[1] << 8) | (ns[2] << 4) | ns[3]


def bytes_to_block(hi, lo):
    """两个字节拼成一个 16 bit 分组。"""
    return ((hi & 0xFF) << 8) | (lo & 0xFF)


def block_to_bytes(block):
    """16 bit 分组拆成 (高字节, 低字节)。"""
    return (block >> 8) & 0xFF, block & 0xFF


def hex16(v, width=4):
    """格式化成大写十六进制，默认 4 位（16 bit）。"""
    return format(v, "0%dX" % width)


# ---------------------------------------------------------------------------
# 四、密钥扩展
# ---------------------------------------------------------------------------

def rot_nib(w):
    """RotNib：交换一个字节的高低半字节，0x2D -> 0xD2"""
    return ((w & 0x0F) << 4) | ((w >> 4) & 0x0F)


def sub_nib(w):
    """SubNib：对一个字节的两个半字节分别查 S 盒。"""
    return (SBOX[(w >> 4) & 0xF] << 4) | SBOX[w & 0xF]


def g_function(w, rcon):
    """
    g 函数 = SubNib(RotNib(w)) ⊕ Rcon
    对应 AES 里的 g 函数（RotWord → SubWord → Rcon），只是字长变短。
    """
    return sub_nib(rot_nib(w)) ^ rcon


def expand_key_words(key):
    """
    密钥扩展：16 bit 主密钥 -> w0..w5 共 6 个字节 -> 3 个 16 bit 轮密钥。

        w2 = w0 ⊕ g(w1, RCON1)
        w3 = w2 ⊕ w1
        w4 = w2 ⊕ g(w3, RCON2)
        w5 = w4 ⊕ w3

    返回 [w0, w1, w2, w3, w4, w5]
    """
    key &= 0xFFFF
    w0 = (key >> 8) & 0xFF
    w1 = key & 0xFF
    w2 = w0 ^ g_function(w1, RCON1)
    w3 = w2 ^ w1
    w4 = w2 ^ g_function(w3, RCON2)
    w5 = w4 ^ w3
    return [w0, w1, w2, w3, w4, w5]


def expand_key(key):
    """返回 3 个轮密钥 (K0, K1, K2)，每个 16 bit。"""
    w = expand_key_words(key)
    return ((w[0] << 8) | w[1],
            (w[2] << 8) | w[3],
            (w[4] << 8) | w[5])


# ---------------------------------------------------------------------------
# 五、轮变换的四个基本操作
# ---------------------------------------------------------------------------

def add_round_key(state, round_key):
    """轮密钥加：按位异或（唯一的“密钥参与”步骤）。"""
    return state ^ round_key


def sub_bytes(state):
    """半字节替换：4 个半字节分别查 S 盒。"""
    return pack([SBOX[x] for x in nibbles(state)])


def inv_sub_bytes(state):
    """逆半字节替换。"""
    return pack([INV_SBOX[x] for x in nibbles(state)])


def shift_rows(state):
    """行移位：第二行循环左移 1 个半字节，即交换 n1 与 n3。

        替换前        替换后
        n0 n1         n0 n3
        n2 n3         n2 n1
    """
    n = nibbles(state)
    n[1], n[3] = n[3], n[1]
    return pack(n)


# 行移位只交换一对半字节，是自逆操作
inv_shift_rows = shift_rows


def mix_columns(state):
    """
    列混淆：对每一列做 GF(2^4) 上的矩阵乘法

        [n0']   [1 4] [n0]        [n2']   [1 4] [n2]
        [n1'] = [4 1] [n1]        [n3'] = [4 1] [n3]
    """
    n = nibbles(state)
    n0 = n[0] ^ gmul(4, n[1])
    n1 = gmul(4, n[0]) ^ n[1]
    n2 = n[2] ^ gmul(4, n[3])
    n3 = gmul(4, n[2]) ^ n[3]
    return pack([n0, n1, n2, n3])


def inv_mix_columns(state):
    """
    逆列混淆：用上面矩阵在 GF(2^4) 中的逆矩阵

        [9 2]
        [2 9]
    """
    n = nibbles(state)
    n0 = gmul(9, n[0]) ^ gmul(2, n[1])
    n1 = gmul(2, n[0]) ^ gmul(9, n[1])
    n2 = gmul(9, n[2]) ^ gmul(2, n[3])
    n3 = gmul(2, n[2]) ^ gmul(9, n[3])
    return pack([n0, n1, n2, n3])


# ---------------------------------------------------------------------------
# 六、单分组加解密
# ---------------------------------------------------------------------------

def encrypt_block(plaintext, key):
    """
    S-AES 加密一个 16 bit 分组。

        0. 轮密钥加 K0
        1. 第 1 轮：半字节替换 → 行移位 → 列混淆 → 轮密钥加 K1
        2. 第 2 轮：半字节替换 → 行移位 → 轮密钥加 K2
    """
    k0, k1, k2 = expand_key(key)
    state = add_round_key(plaintext & 0xFFFF, k0)

    state = sub_bytes(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, k1)

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, k2)
    return state


def decrypt_block(ciphertext, key):
    """
    S-AES 解密：把加密的每一步按相反顺序、相反操作还原。

        0. 轮密钥加 K2
        1. 逆第 2 轮：逆行移位 → 逆半字节替换 → 轮密钥加 K1 → 逆列混淆
        2. 逆第 1 轮：逆行移位 → 逆半字节替换 → 轮密钥加 K0
    """
    k0, k1, k2 = expand_key(key)
    state = add_round_key(ciphertext & 0xFFFF, k2)

    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, k1)
    state = inv_mix_columns(state)

    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, k0)
    return state


# ---------------------------------------------------------------------------
# 七、带中间过程的版本（用于演示、GUI、调试）
# ---------------------------------------------------------------------------

def encrypt_block_trace(plaintext, key):
    """
    返回 (密文, 步骤列表)
    步骤列表元素为 (说明, 当前状态值)，方便打印每一轮的中间状态。
    """
    w = expand_key_words(key)
    k0, k1, k2 = expand_key(key)
    steps = []

    state = add_round_key(plaintext & 0xFFFF, k0)
    steps.append(("轮密钥加 K0", state))

    state = sub_bytes(state)
    steps.append(("第 1 轮 · 半字节替换", state))
    state = shift_rows(state)
    steps.append(("第 1 轮 · 行移位", state))
    state = mix_columns(state)
    steps.append(("第 1 轮 · 列混淆", state))
    state = add_round_key(state, k1)
    steps.append(("第 1 轮 · 轮密钥加 K1", state))

    state = sub_bytes(state)
    steps.append(("第 2 轮 · 半字节替换", state))
    state = shift_rows(state)
    steps.append(("第 2 轮 · 行移位", state))
    state = add_round_key(state, k2)
    steps.append(("第 2 轮 · 轮密钥加 K2（输出密文）", state))

    return state, steps, w


def decrypt_block_trace(ciphertext, key):
    """解密过程的逐步追踪。"""
    k0, k1, k2 = expand_key(key)
    steps = []

    state = add_round_key(ciphertext & 0xFFFF, k2)
    steps.append(("轮密钥加 K2", state))

    state = inv_shift_rows(state)
    steps.append(("逆第 2 轮 · 逆行移位", state))
    state = inv_sub_bytes(state)
    steps.append(("逆第 2 轮 · 逆半字节替换", state))
    state = add_round_key(state, k1)
    steps.append(("逆第 2 轮 · 轮密钥加 K1", state))
    state = inv_mix_columns(state)
    steps.append(("逆第 2 轮 · 逆列混淆", state))

    state = inv_shift_rows(state)
    steps.append(("逆第 1 轮 · 逆行移位", state))
    state = inv_sub_bytes(state)
    steps.append(("逆第 1 轮 · 逆半字节替换", state))
    state = add_round_key(state, k0)
    steps.append(("逆第 1 轮 · 轮密钥加 K0（输出明文）", state))

    return state, steps


if __name__ == "__main__":
    # 自检：教科书附录 D 的例题
    assert build_sbox() == SBOX, "S 盒推导结果与表 D.1 不一致"
    k = expand_key(0x2D55)
    print("密钥 2D55 的轮密钥:", [hex16(x) for x in k])
    c = encrypt_block(0x6BA3, 0x2D55)
    print("加密 6BA3 ->", hex16(c), "(教科书答案 3C3B)")
    print("解密回原值 ->", hex16(decrypt_block(c, 0x2D55)))
