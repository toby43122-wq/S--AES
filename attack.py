# -*- coding: utf-8 -*-
"""
中间相遇攻击（Meet-in-the-Middle）
=================================

对应作业第 4 关 4.2：已知一组（或多组）使用同一对密钥的明密文对，
用中间相遇攻击恢复双重加密的密钥 Key(K1 + K2)。

攻击原理：
    C = E(K2, E(K1, P))
    正向：对全部 2^16 个 K1 计算 X = E(K1, P)，建立 X -> {K1} 的表
    反向：对全部 2^16 个 K2 计算 X = D(K2, C)，查表求交集
    命中项再用额外的明密文对过滤误报

为什么它有效：双重加密的名义密钥空间是 2^32，但攻击只需要约 2^17 的工作量。
这就是 2DES 被淘汰的原因，也是作业要求做这个实验的意义。
"""

from saes import decrypt_block, encrypt_block

TOTAL_KEYS = 0x10000  # 16 bit 密钥空间


def double_encrypt(plaintext, key1, key2):
    """双重加密：C = E(K2, E(K1, P))"""
    return encrypt_block(encrypt_block(plaintext, key1), key2)


def double_decrypt(ciphertext, key1, key2):
    """双重解密：P = D(K1, D(K2, C))"""
    return decrypt_block(decrypt_block(ciphertext, key2), key1)


def meet_in_the_middle(pairs):
    """
    执行中间相遇攻击。

    参数：
        pairs: [(明文, 密文), ...]，至少一组；多组可以进一步过滤误报
    返回：
        (候选密钥列表 [(k1, k2), ...], 统计信息 dict)
    """
    if not pairs:
        raise ValueError("至少需要一组明密文对")

    first_plain, first_cipher = pairs[0]

    # 第一步：正向建表，X = E(K1, P)
    forward_table = {}
    for key1 in range(TOTAL_KEYS):
        middle_value = encrypt_block(first_plain, key1)
        forward_table.setdefault(middle_value, []).append(key1)

    # 第二步：反向查找，X = D(K2, C)
    candidates = []
    for key2 in range(TOTAL_KEYS):
        middle_value = decrypt_block(first_cipher, key2)
        matched = forward_table.get(middle_value)
        if matched:
            for key1 in matched:
                candidates.append((key1, key2))

    # 第三步：用其余明密文对过滤误报
    survivors = []
    for key1, key2 in candidates:
        if all(double_encrypt(pt, key1, key2) == ct for pt, ct in pairs):
            survivors.append((key1, key2))

    stats = {
        "keys_scanned": TOTAL_KEYS,
        "first_hits": len(candidates),
        "survivors": len(survivors),
    }
    return survivors, stats


def recover_key32(pairs):
    """
    攻击并返回 32 bit 密钥（K1 在高 16 位，K2 在低 16 位）。
    若存在多个候选，返回第一个；调用方可用 stats 判断是否唯一。
    """
    survivors, stats = meet_in_the_middle(pairs)
    if not survivors:
        return None, stats
    key1, key2 = survivors[0]
    return ((key1 << 16) | key2), stats


if __name__ == "__main__":
    plaintext = 0x6BA3
    real_key1, real_key2 = 0x2D55, 0xA1B2
    cipher = double_encrypt(plaintext, real_key1, real_key2)

    found, info = meet_in_the_middle([(plaintext, cipher)])
    print("已知：P = %04X, C = %04X" % (plaintext, cipher))
    print("命中 %d 组候选，过滤后 %d 组" % (info["first_hits"], info["survivors"]))
    for k1, k2 in found[:5]:
        print("  K1 = %04X, K2 = %04X -> Key = %08X" % (k1, k2, (k1 << 16) | k2))
