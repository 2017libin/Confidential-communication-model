from Crypto.Hash import SHA256  # 对消息使用的哈希函数
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import AES  # 传输方式加密算法
import base64  # 传输数据编码格式
from Crypto.Util.py3compat import bchr, bord

# 填充函数: data填充至block的倍数
def pad(data_to_pad, block_size):
    padding_len = block_size-len(data_to_pad)%block_size
    padding = bchr(padding_len)*padding_len
    return data_to_pad + padding

# 返回未填充的data
def unpad(padded_data, block_size):
    pdata_len = len(padded_data)
    if pdata_len % block_size:
        raise ValueError("Input data is not padded")
    padding_len = bord(padded_data[-1])  
    if padding_len<1 or padding_len>min(block_size, pdata_len):
        raise ValueError("Padding is incorrect.")
    if padded_data[-padding_len:]!=bchr(padding_len)*padding_len:
        raise ValueError("PKCS#7 padding is incorrect.")
    return padded_data[:-padding_len]

# 以字节流的形式返回文件内容
def read_file_by_byte(filename:str):
    f = open(filename, 'rb')
    content = f.read()
    f.close()
    return content

# 以字节流的形式返回签名值
# 输入：md表示使用消息M得到的哈希实体（注意不是哈希值）
def signature(bytes, rsa_path):
    # 使用字节流来更新md
    md = SHA256.new()
    md.update(bytes)

    with open(rsa_path, 'r') as f:
        key = f.read()
        rsakey = RSA.importKey(key)  
        signer = PKCS1_v1_5.new(rsakey)  # 使用私钥构建签名实体
        signature = signer.sign(md)

        return signature

# 返回true或者false，表示验证签名成功或者失败
def verify_signature(bytes, signature, pub_rsa_path):
    # 使用字节流来更新md
    md = SHA256.new()
    md.update(bytes)

    with open(pub_rsa_path, 'r') as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        verifier = PKCS1_v1_5.new(rsakey)  # 使用公钥构建验签实体
        is_verify = verifier.verify(md, signature)

        return is_verify

# 生成rsa私钥和公钥并且保存到文件中
def gen_rsa_key():
    # 生成rsa密钥实体
    rsa = RSA.generate(1024)  # 生成的私钥长度为1024

    # 导出私钥和公钥到文件
    rsa_pk = rsa.exportKey()  # rsa私钥
    rsa_pubk = rsa.publickey().exportKey()  # rsa公钥
    with open("rsa_pk.key", "wb") as f1:
        f1.write(rsa_pk)
    with open("rsa_pubk.crt", "wb") as f2:
        f2.write(rsa_pubk)

# 将src文件的内容进行保密处理后存入dst文件中
def send2(src_path:str, dst_path:str):
    # 以字节流的方式读取文件内容
    bytes = read_file_by_byte(src_path)  # 以字节的形式返回文件内容

    # 对文件进行hash
    md = SHA256.new()
    md.update(bytes)
    hash_value = md.digest()
    
    # 使用AES对 消息||加密的哈希值 进行加密
    aes_key = b"0123456789abcdef"
    iv = b"0123456789abcdef"
    aes_obj = AES.new(aes_key, AES.MODE_CBC, iv)  # 面向分组的传输使用CBC加密模式
    padded_plaintext = pad(bytes+hash_value, AES.block_size)
    ciphertext = aes_obj.encrypt(padded_plaintext)
    
    # 密文使用base64编码
    encoded_ciphertext = base64.encodebytes(ciphertext)
    
    # 写入到目标文件
    with open(dst_path, 'wb') as f:
        f.write(encoded_ciphertext)

# 对收到的src文件的保密内容进行解密和验证后放入dst文件中
def receive2(src_path:str, dst_path):
    # 以字节流的方式读取文件内容
    encoded_ciphertext = read_file_by_byte(src_path)  # 以字节的形式返回文件内容

    # 使用base64编码对密文进行解码
    ciphertext = base64.decodebytes(encoded_ciphertext)

    # 使用AES对 消息||哈希值 进行解密
    aes_key = b"0123456789abcdef"
    iv = b"0123456789abcdef"
    aes_obj = AES.new(aes_key, AES.MODE_CBC, iv)  # 面向分组的传输使用CBC加密模式
    padded_plaintext = aes_obj.decrypt(ciphertext)

    plaintext = unpad(padded_plaintext, AES.block_size)

    # 获取文件内容和签名值
    bytes = plaintext[:-32]
    hash_value1 = plaintext[-32:]

    # 验证哈希值是否一致
    # 对文件进行hash
    md = SHA256.new()
    md.update(bytes)
    hash_value2 = md.digest()

    if hash_value1 == hash_value2:
        with open(dst_path, 'wb') as f:
            f.write(bytes)
    else:
        print("检验失败!")

# 将src文件的内容进行保密处理后存入dst文件中
def send3(src_path:str, dst_path:str):
    # 以字节流的方式读取文件内容
    bytes = read_file_by_byte(src_path)  # 以字节的形式返回文件内容

    # 对文件进行签名
    sign = signature(bytes, "rsa_pk.key")
    
    # 使用AES对 消息||加密的哈希值 进行加密
    aes_key = b"0123456789abcdef"
    iv = b"0123456789abcdef"
    aes_obj = AES.new(aes_key, AES.MODE_CBC, iv)  # 面向分组的传输使用CBC加密模式
    padded_plaintext = pad(bytes+sign, AES.block_size)
    ciphertext = aes_obj.encrypt(padded_plaintext)
    
    # 密文使用base64编码
    encoded_ciphertext = base64.encodebytes(ciphertext)
    
    # 写入到目标文件
    with open(dst_path, 'wb') as f:
        f.write(encoded_ciphertext)

# 对收到的src文件的保密内容进行解密和验证后放入dst文件中
def receive3(src_path:str, dst_path):
    # 以字节流的方式读取文件内容
    encoded_ciphertext = read_file_by_byte(src_path)  # 以字节的形式返回文件内容

    # 使用base64编码对密文进行解码
    ciphertext = base64.decodebytes(encoded_ciphertext)

    # 使用AES对 消息||签名 进行解密
    aes_key = b"0123456789abcdef"
    iv = b"0123456789abcdef"
    aes_obj = AES.new(aes_key, AES.MODE_CBC, iv)  # 面向分组的传输使用CBC加密模式
    padded_plaintext = aes_obj.decrypt(ciphertext)

    plaintext = unpad(padded_plaintext, AES.block_size)

    # 获取文件内容和签名值
    bytes = plaintext[:-32]
    sign = plaintext[-32:]

    # 验证签名是否通过
    if verify_signature(bytes, sign, "rsa_pubk.crt"):
        with open(dst_path, 'wb') as f:
            f.write(bytes)
    else:
        print("验签失败!")

if __name__ == "__main__":


    send2("test","111")
    receive2("111", "222")
    # gen_rsa_key()