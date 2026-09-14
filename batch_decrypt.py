# -*- coding: utf-8 -*-
"""
XBee 批量解密与加密工具 (支持 CSV/TXT 批量处理)
"""

import sys
import os
import csv
import base64
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

class XBeeDES:
    @staticmethod
    def _java_get_chr_int(ch: str) -> int:
        """1:1 还原 Java 源码中的 getChrInt 漏洞逻辑（不识别小写字母）"""
        if ch in '0123456789':
            return int(ch)
        elif ch in 'ABCDEF':
            return ord(ch) - ord('A') + 10
        else:
            return 0  # 核心漏洞点：小写字母 a-f 到了这里全部变成了 0

    @classmethod
    def _get_key_by_str(cls, key_str: str) -> bytes:
        """1:1 还原 Java 源码中的 getKeyByStr 逻辑"""
        b_ret = bytearray(len(key_str) // 2)
        for i in range(len(key_str) // 2):
            high = cls._java_get_chr_int(key_str[2 * i])
            low = cls._java_get_chr_int(key_str[2 * i + 1])
            b_ret[i] = (16 * high + low) & 0xFF
        return bytes(b_ret)

    @classmethod
    def decode(cls, ciphertext_base64: str, key_string: str = "9b2648fcdfbad80f") -> str:
        """解密方法"""
        if not ciphertext_base64 or not ciphertext_base64.strip():
            return ""
        try:
            real_key = cls._get_key_by_str(key_string)
            cipher = DES.new(real_key, DES.MODE_ECB)
            encrypted_bytes = base64.b64decode(ciphertext_base64.strip().encode('utf-8'))
            decrypted_padded = cipher.decrypt(encrypted_bytes)
            decrypted_bytes = unpad(decrypted_padded, DES.block_size)
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            return f"[解密失败: {str(e)}]"

    @classmethod
    def encode(cls, plaintext: str, key_string: str = "9b2648fcdfbad80f") -> str:
        """加密方法"""
        if not plaintext:
            return ""
        try:
            real_key = cls._get_key_by_str(key_string)
            cipher = DES.new(real_key, DES.MODE_ECB)
            padded_bytes = pad(plaintext.encode('utf-8'), DES.block_size)
            encrypted_bytes = cipher.encrypt(padded_bytes)
            return base64.b64encode(encrypted_bytes).decode('utf-8')
        except Exception as e:
            return f"[加密失败: {str(e)}]"

def print_help():
    print("=" * 60)
    print(" 使用说明:")
    print("  1. 单个快速解密: python batch_decrypt.py -d <密文>")
    print("  2. 单个快速加密: python batch_decrypt.py -e <明文>")
    print("  3. 批量处理文件: python batch_decrypt.py <输入文件> [输出文件]")
    print("     - 支持 .txt 文件 (每行一个密文)")
    print("     - 支持 .csv 文件 (自动识别并在旁边生成解密列)")
    print("=" * 60)

def batch_process(input_path, output_path=None):
    if not os.path.exists(input_path):
        print(f"❌ 错误: 输入文件 [{input_path}] 不存在！")
        return

    if not output_path:
        base, ext = os.path.splitext(input_path)
        output_path = f"{base}_result{ext}"

    ext = os.path.splitext(input_path)[1].lower()

    if ext == '.csv':
        # CSV 批量处理
        try:
            with open(input_path, 'r', encoding='utf-8-sig') as f_in,                  open(output_path, 'w', encoding='utf-8', newline='') as f_out:
                reader = csv.reader(f_in)
                writer = csv.writer(f_out)
                
                header = next(reader, None)
                if header:
                    writer.writerow(header + ["解密结果", "加密结果(测试)"])
                
                count = 0
                for row in reader:
                    if not row:
                        writer.writerow([])
                        continue
                    # 默认假设首列是需要处理的数据
                    raw_data = row[0]
                    decrypted = XBeeDES.decode(raw_data)
                    # 如果解密失败（返回错误提示），则说明原数据可能是明文，尝试提供加密参考
                    encrypted = XBeeDES.encode(raw_data) if "[解密失败" in decrypted else ""
                    
                    writer.writerow(row + [decrypted, encrypted])
                    count += 1
            print(f"📊 CSV 批量处理完成！已处理 {count} 行数据。")
            print(f"💾 结果已保存至: {output_path}")
        except Exception as e:
            print(f"❌ 处理 CSV 失败: {e}")

    else:
        # 默认作为 TXT 按行批量处理
        try:
            with open(input_path, 'r', encoding='utf-8') as f_in,                  open(output_path, 'w', encoding='utf-8') as f_out:
                lines = f_in.readlines()
                count = 0
                for line in lines:
                    striped_line = line.strip()
                    if not striped_line:
                        f_out.write("\n")
                        continue
                    decrypted = XBeeDES.decode(striped_line)
                    f_out.write(f"密文: {striped_line}  --> 解密明文: {decrypted}\n")
                    count += 1
            print(f"📊 TXT 批量处理完成！已处理 {count} 行数据。")
            print(f"💾 结果已保存至: {output_path}")
        except Exception as e:
            print(f"❌ 处理 TXT 失败: {e}")

if __name__ == '__main__':
    args = sys.argv[1:]
    if not args or "-h" in args or "--help" in args:
        print_help()
        sys.exit(0)

    if args[0] == "-d" and len(args) > 1:
        print(f"明文结果: {XBeeDES.decode(args[1])}")
    elif args[0] == "-e" and len(args) > 1:
        print(f"密文结果: {XBeeDES.encode(args[1])}")
    else:
        in_file = args[0]
        out_file = args[1] if len(args) > 1 else None
        batch_process(in_file, out_file)
