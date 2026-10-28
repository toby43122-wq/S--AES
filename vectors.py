# -*- coding: utf-8 -*-
"""
标准测试向量的生成
==================

`data/vectors.json` 是组间交叉测试（第 2 关）的对齐依据：
两边用同样的密钥、同样的明文，必须得到同样的密文。

这里集中定义向量的生成逻辑，供三处复用：
    * tools/make_vectors.py —— 命令行重新生成
    * gui.py 的“交叉测试”页 —— 导出给我方 / 校验对方
    * tests/test_all.py    —— 逐条回归

每个用例带一个 level 字段，指明它对应作业的哪一关，方便写测试报告。
"""

import json
import os

from saes import encrypt_block, hex16
from modes import decrypt_block_multi, decrypt_data, encrypt_block_multi, encrypt_data

VERSION = "S-AES-INTEROP-1"
VECTORS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "vectors.json")


def _block_case(case_id, level, desc, keys, plaintext):
    """单分组用例：明文、密文都是 4 位十六进制。"""
    keys_int = [int(k, 16) for k in keys]
    cipher = encrypt_block_multi(plaintext, keys_int)
    return {
        "id": case_id,
        "level": level,
        "desc": desc,
        "hex_data": False,
        "keys": keys,
        "plaintext": hex16(plaintext),
        "ciphertext": hex16(cipher),
    }


def _data_case(case_id, level, desc, keys, text, chain="ecb", iv="0000"):
    """多分组用例：明文、密文都是任意长的十六进制字节串。"""
    keys_int = [int(k, 16) for k in keys]
    data = text.encode("utf-8")
    cipher = encrypt_data(data, keys_int, chain, int(iv, 16))
    return {
        "id": case_id,
        "level": level,
        "desc": desc,
        "hex_data": True,
        "keys": keys,
        "chain": chain,
        "iv": iv,
        "plaintext": data.hex().upper(),
        "ciphertext": cipher.hex().upper(),
    }


def build_cases():
    """返回完整的协议文档（含 8 条用例，覆盖 5 个关卡）。"""
    return [
        _block_case(1, "1", "教科书附录 D 例题（唯一权威答案：3C3B）", ["2D55"], 0x6BA3),
        _block_case(2, "1", "全零明文 + 全零密钥（边界用例）", ["0000"], 0x0000),
        _block_case(3, "1", "参考向量 D728 + 4AF5", ["4AF5"], 0xD728),
        _data_case(4, "3", "ASCII 字符串 \"Hello!\"（3 字节，需填充）", ["2D55"], "Hello!"),
        _block_case(5, "4.1", "双重加密，密钥 32 bit = 2D55A1B2", ["2D55", "A1B2"], 0x6BA3),
        _block_case(6, "4.3", "三重加密（32 bit 密钥 2D55A1B2，即 K1K2K1）",
                    ["2D55", "A1B2", "2D55"], 0x6BA3),
        _block_case(7, "4.3", "三重加密（48 bit 密钥 2D55A1B20F0F）",
                    ["2D55", "A1B2", "0F0F"], 0x6BA3),
        _data_case(8, "5", "CBC 长文本，IV=1234", ["2D55"], "S-AES CBC TEST", "cbc", "1234"),
        _data_case(9, "5", "CBC + 双重加密，IV=5678",
                   ["2D55", "A1B2"], "hello SAES", "cbc", "5678"),
    ], {
        "version": VERSION,
        "algorithm": "S-AES (Simplified AES, Appendix D)",
        "block_size_bits": 16,
        "key_size_bits": 16,
        "padding": "PKCS#7 over 2-byte blocks",
    }


def build_spec():
    """组装成可直接写入 JSON 的字典。"""
    cases, meta = build_cases()
    meta["cases"] = cases
    return meta


def save(path=VECTORS_PATH):
    """生成并写入向量文件，返回写入路径。"""
    spec = build_spec()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as file:
        json.dump(spec, file, ensure_ascii=False, indent=2)
    return path


def load(path=VECTORS_PATH):
    """读取向量文件。"""
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def verify_case(case):
    """
    逐条校验一个用例，返回结果字典。
    既检查“加密结果是否一致”，也检查“能否解回原明文”。
    """
    keys = [int(k, 16) for k in case["keys"]]
    chain = case.get("chain", "ecb")
    iv = int(case.get("iv", "0000"), 16)
    plain_hex = case["plaintext"].upper()
    cipher_hex = case["ciphertext"].upper()

    if case.get("hex_data"):
        plain_bytes = bytes.fromhex(plain_hex)
        got = encrypt_data(plain_bytes, keys, chain, iv).hex().upper()
        back = decrypt_data(bytes.fromhex(cipher_hex), keys, chain, iv).hex().upper()
    else:
        plain_block = int(plain_hex, 16)
        got = hex16(encrypt_block_multi(plain_block, keys))
        back = hex16(decrypt_block_multi(int(cipher_hex, 16), keys))

    return {
        "id": case.get("id"),
        "level": case.get("level", "?"),
        "desc": case.get("desc", ""),
        "ok_encrypt": got == cipher_hex,
        "ok_decrypt": back == plain_hex,
        "got": got,
        "expected": cipher_hex,
        "back": back,
        "expected_plain": plain_hex,
    }


def verify_spec(spec):
    """校验整个协议文档，返回 (结果列表, 通过数, 总数)。"""
    results = [verify_case(case) for case in spec.get("cases", [])]
    passed = sum(1 for item in results if item["ok_encrypt"] and item["ok_decrypt"])
    return results, passed, len(results)


if __name__ == "__main__":
    print(save())
