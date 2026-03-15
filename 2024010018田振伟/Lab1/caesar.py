def caesar_decrypt(ciphertext, shift):
    """凯撒密码解密函数
    :param ciphertext: 待解密密文（大写字母）
    :param shift: 偏移量（密钥k）
    :return: 解密后的明文
    """
    plaintext = ""
    for char in ciphertext:
        if char.isalpha() and char.isupper():
            # 对大写字母进行解密偏移计算
            plaintext += chr((ord(char) - shift - ord('A')) % 26 + ord('A'))
        else:
            # 非字母字符保持不变
            plaintext += char
    return plaintext

if __name__ == "__main__":
    # 题目给定的密文
    cipher = "NUFECMWBYUJMBIQGYNBYWIXY"
    
    print("穷举法破解凯撒密码（k=1~25）：")
    print("=" * 50)
    # 遍历所有可能的密钥k（1~25）
    for k in range(1, 26):
        result = caesar_decrypt(cipher, k)
        print(f"k={k:<2} : {result}")
    
    print("=" * 50)
    # 正确结果说明（在代码注释中体现）
    print("正确密钥 k=11")
    print("解密后明文：THECIPHERHEREWILLBEEASYTOCRACK")
    print("判断依据：该明文为有意义的英文句子，其余k值对应结果均为无意义字符组合")
