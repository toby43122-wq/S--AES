# -*- coding: utf-8 -*-
"""
多重加密 + 分组工作模式
=======================

本文件把两个“扩展功能”做成可组合的两层：

    内层：多重加密（1 重 / 2 重 / 3 重“加密-解密-加密”）
    外层：工作模式（ECB 电码本 / CBC 密码分组链）

组合方式与 3DES-CBC 完全一致：先用多重加密处理单个分组，再用 CBC 把分组链起来。

S-AES 的分组只有 16 bit（2 字节），所以：
    * 任意长度的字节串按 2 字节切块；
    * 不足 2 字节的用 PKCS#7 补足；
    * CBC 的初始向量 IV 也是 16 bit。
"""

from saes import (block_to_bytes, bytes_to_block, decrypt_block,
                  encrypt_block, hex16)

BLOCK_SIZE = 2  # 字节


# ---------------------------------------------------------------------------
# 一、多重加密（对应第 9 讲“多重加密”）
# ---------------------------------------------------------------------------

def check_keys(keys):
    """把密钥统一成 list[int]，并拒绝空列表。"""
    if isinstance(keys, int):
        keys = [keys]
    keys = [k & 0xFFFF for k in keys]
    if not 1 <= len(keys) <= 3:
        raise ValueError("密钥个数必须是 1、2 或 3")
    return keys


def encrypt_block_multi(block, keys):
    """
    对单个 16 bit 分组做多重加密。

        1 重：C = E(K1, P)
        2 重：C = E(K2, E(K1, P))                     —— 对应 2DES
        3 重：C = E(K3, D(K2, E(K1, P)))              —— 对应 3DES 的 EDE 结构
    """
    keys = check_keys(keys)
    if len(keys) == 1:
        return encrypt_block(block, keys[0])
    if len(keys) == 2:
        return encrypt_block(encrypt_block(block, keys[0]), keys[1])
    # 三重：加密 → 解密 → 加密，中间用解密是为了兼容“两把钥匙的三重加密”
    return encrypt_block(
        decrypt_block(encrypt_block(block, keys[0]), keys[1]), keys[2])


def decrypt_block_multi(block, keys):
    """多重加密的逆过程，顺序与加密完全相反。"""
    keys = check_keys(keys)
    if len(keys) == 1:
        return decrypt_block(block, keys[0])
    if len(keys) == 2:
        return decrypt_block(decrypt_block(block, keys[1]), keys[0])
    return decrypt_block(
        encrypt_block(decrypt_block(block, keys[2]), keys[1]), keys[0])


# ---------------------------------------------------------------------------
# 二、填充（PKCS#7）
# ---------------------------------------------------------------------------

def pad(data):
    """不足 2 字节整数倍时补齐；恰好整除时补一整块 0x02 0x02。"""
    n = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([n]) * n


def unpad(data):
    """去掉填充，同时校验填充是否合法（可用于发现密钥错误或数据被篡改）。"""
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("密文长度不是分组大小的整数倍，数据可能已损坏")
    n = data[-1]
    if not 1 <= n <= BLOCK_SIZE:
        raise ValueError("填充值非法，密钥错误或密文被篡改")
    if data[-n:] != bytes([n]) * n:
        raise ValueError("填充内容不一致，密钥错误或密文被篡改")
    return data[:-n]


# ---------------------------------------------------------------------------
# 三、工作模式（对应第 9 讲 ECB / CBC）
# ---------------------------------------------------------------------------

def _split_blocks(data):
    return [bytes_to_block(data[i], data[i + 1])
            for i in range(0, len(data), BLOCK_SIZE)]


def _join_blocks(blocks):
    out = bytearray()
    for b in blocks:
        hi, lo = block_to_bytes(b)
        out += bytes([hi, lo])
    return bytes(out)


def encrypt_data(data, keys, chain="ecb", iv=0x0000):
    """
    加密任意长度字节串。

    chain="ecb"：每个分组独立加密（相同明文块 -> 相同密文块，会泄露模式）
    chain="cbc"：C_i = E(P_i ⊕ C_{i-1})，C_0 = IV，需要 16 bit 的 IV
    """
    keys = check_keys(keys)
    data = pad(bytes(data)) if data is not None else pad(b"")

    blocks = _split_blocks(data)
    out = []

    if chain == "ecb":
        for b in blocks:
            out.append(encrypt_block_multi(b, keys))
    elif chain == "cbc":
        prev = iv & 0xFFFF
        for b in blocks:
            c = encrypt_block_multi(b ^ prev, keys)
            out.append(c)
            prev = c
    else:
        raise ValueError("chain 只支持 'ecb' 或 'cbc'")
    return _join_blocks(out)


def decrypt_data(data, keys, chain="ecb", iv=0x0000):
    """解密任意长度字节串，并去掉 PKCS#7 填充。"""
    keys = check_keys(keys)
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("密文长度必须是 %d 字节的整数倍" % BLOCK_SIZE)

    blocks = _split_blocks(bytes(data))
    out = []

    if chain == "ecb":
        for b in blocks:
            out.append(decrypt_block_multi(b, keys))
    elif chain == "cbc":
        prev = iv & 0xFFFF
        for b in blocks:
            out.append(decrypt_block_multi(b, keys) ^ prev)
            prev = b
    else:
        raise ValueError("chain 只支持 'ecb' 或 'cbc'")
    return unpad(_join_blocks(out))


# ---------------------------------------------------------------------------
# 四、密钥的表示与解析（第 4 关：32 bit / 48 bit 密钥）
# ---------------------------------------------------------------------------

def split_key32(key32):
    """
    把 32 bit 密钥拆成两把 16 bit 密钥：高 16 位为 K1，低 16 位为 K2。
    例：0x2D55A1B2 -> (0x2D55, 0xA1B2)
    """
    key32 &= 0xFFFFFFFF
    return (key32 >> 16) & 0xFFFF, key32 & 0xFFFF


def split_key48(key48):
    """把 48 bit 密钥拆成三把 16 bit 密钥。"""
    key48 &= 0xFFFFFFFFFFFF
    return (key48 >> 32) & 0xFFFF, (key48 >> 16) & 0xFFFF, key48 & 0xFFFF


def join_key32(key1, key2):
    """把两把 16 bit 密钥拼成一个 32 bit 密钥，用于界面显示。"""
    return ((key1 & 0xFFFF) << 16) | (key2 & 0xFFFF)


def parse_key_text(text):
    """
    解析界面上输入的密钥字符串，返回 1~3 把密钥。

        4 位十六进制  "2D55"           -> [K1]
        8 位十六进制  "2D55A1B2"       -> [K1, K2]
        12 位十六进制 "2D55A1B20F0F"   -> [K1, K2, K3]
    """
    clean = text.strip().replace(" ", "").replace("0x", "").replace("0X", "")
    if not clean or any(c not in "0123456789abcdefABCDEF" for c in clean):
        raise ValueError("密钥必须是十六进制，例如 2D55 / 2D55A1B2 / 2D55A1B20F0F")
    if len(clean) == 4:
        return [int(clean, 16)]
    if len(clean) == 8:
        return list(split_key32(int(clean, 16)))
    if len(clean) == 12:
        return list(split_key48(int(clean, 16)))
    raise ValueError("密钥长度必须是 4、8 或 12 位十六进制")


def triple_keys_from_32(key32):
    """
    第 4 关 4.3(1)：用 32 bit 密钥做三重加密，即 K1=K3、K2 居中。
    返回 [K1, K2, K1]。
    """
    key1, key2 = split_key32(key32)
    return [key1, key2, key1]


# ---------------------------------------------------------------------------
# 五、ASCII 字符串支持（第 3 关）
# ---------------------------------------------------------------------------

def ascii_to_bytes(text):
    """
    把 ASCII 字符串转成字节串（每字符 1 字节）。
    非 ASCII 字符会报错 —— 第 3 关要求的就是 ASCII，中文请走 UTF-8 接口。
    """
    try:
        return text.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("第 3 关只接受 ASCII 字符（0x00~0x7F），中文请用 UTF-8 模式")


def bytes_to_ascii(data):
    """
    把字节串按 latin-1 还原成字符串。密文几乎必然是乱码，
    但 latin-1 保证“1 字节 = 1 字符”，可以原样复制回去解密。
    """
    return data.decode("latin-1")


def ascii_preview(data):
    """
    给界面显示的“可读版”ASCII：可打印字符原样显示，
    控制字符（0x00~0x1F、0x7F）显示为 ·，方便看出乱码范围。
    """
    return "".join(chr(b) if 0x20 <= b <= 0x7E else "·" for b in data)


# ---------------------------------------------------------------------------
# 六、CBC 的 IV 与密文篡改实验（第 5 关）
# ---------------------------------------------------------------------------

def random_iv():
    """随机生成 16 bit 初始向量。"""
    import random
    return random.getrandbits(16)


def flip_bit(data, block_index, bit_index):
    """
    翻转指定分组中的某一位，用于第 5 关的“篡改密文”实验。

    block_index: 分组序号，从 0 开始
    bit_index:   分组内位序号，1~16，1 表示该分组最高位（最左边那一位）
    """
    data = bytearray(data)
    block_count = len(data) // BLOCK_SIZE
    if not 0 <= block_index < block_count:
        raise ValueError("分组序号超出范围（共 %d 个分组）" % block_count)
    if not 1 <= bit_index <= 16:
        raise ValueError("位序号必须在 1~16 之间")

    offset = block_index * BLOCK_SIZE
    block = bytes_to_block(data[offset], data[offset + 1])
    block ^= 1 << (16 - bit_index)          # 第 1 位是最高位，所以左移 16-1
    high, low = block_to_bytes(block)
    data[offset], data[offset + 1] = high, low
    return bytes(data)


def split_blocks(data):
    """把字节串按 2 字节切成列表，供界面逐块展示。"""
    return [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


# ---------------------------------------------------------------------------
# 七、便捷封装
# ---------------------------------------------------------------------------

def encrypt_text(text, keys, chain="ecb", iv=0x0000):
    """文本（UTF-8）加密，返回十六进制字符串。"""
    return encrypt_data(text.encode("utf-8"), keys, chain, iv).hex().upper()


def decrypt_text(hex_cipher, keys, chain="ecb", iv=0x0000):
    """十六进制字符串解密，返回文本。"""
    return decrypt_data(bytes.fromhex(hex_cipher), keys, chain, iv).decode("utf-8")


def describe(keys, chain, iv):
    keys = check_keys(keys)
    if len(keys) == 1:
        name = "单重 S-AES"
    elif len(keys) == 2:
        name = "双重加密(2-S-AES, 32 bit 密钥)"
    elif keys[0] == keys[2]:
        name = "三重加密(3-S-AES, 32 bit 密钥 K1K2K1)"
    else:
        name = "三重加密(3-S-AES, 48 bit 密钥 K1K2K3)"
    return "%s · %s · IV=%s" % (name, chain.upper(), hex16(iv))


if __name__ == "__main__":
    keys = [0x2D55, 0xA1B2]
    text = "信息安全导论 - S-AES 作业"
    ct = encrypt_text(text, keys, "cbc", 0x1234)
    print(describe(check_keys(keys), "cbc", 0x1234))
    print("密文:", ct)
    print("解密:", decrypt_text(ct, keys, "cbc", 0x1234))
