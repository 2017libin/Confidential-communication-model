from os import openpty  
from Crypto.Hash import SHA256  # 对消息使用的哈希函数
from Crypto.PublicKey import RSA
from Crypto import Random  
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES  # 传输方式加密算法
import base64  # 传输数据编码格式
from Crypto.Util.py3compat import bchr, bord

# 填充函数
def pad(data_to_pad, block_size):
    padding_len = block_size-len(data_to_pad)%block_size
    padding = bchr(padding_len)*padding_len
    return data_to_pad + padding

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
def signature(md, rsa_path):
    with open(rsa_path, 'r') as f:
        key = f.read()
        rsakey = RSA.importKey(key)  
        signer = PKCS1_v1_5.new(rsakey)  # 使用私钥构建签名实体
        signature = signer.sign(md)

        return signature

# 返回true或者false，表示验证签名成功或者失败
def verify_signature(md, signature, pub_rsa_path):
    '''验证签名'''
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
    
# 发送数据：
def send(src_path:str, dst_path:str):

    # 以字节流的方式读取文件内容
    bytes = read_file_by_byte(src_path)  # 以字节的形式返回文件内容

    # 计算文件的哈希值
    md = SHA256.new()
    md.update(bytes)
    hash = md.digest()  # 返回字节流
    
    # 对文件的哈希值进行加密
    with open("rsa_pk.key", "r") as f:
        rsa_pk = RSA.importKey(f.read())
        encrypted_hash = rsa_pk.encrypt(hash, 0)[0]
        # encryptor = PKCS1_OAEP.new(rsa_pk)
        # encrypted_hash = encryptor.encrypt(hash)  # 使用私钥对hash字节流进行加密

    print(type(encrypted_hash))
    with open("rsa_pubk.crt", "r") as f:
        rsa_pubk = RSA.importKey(f.read())

        # encryptor = PKCS1_OAEP.new(rsa_pubk)
        abc = rsa_pubk.encrypt(encrypted_hash, 0)[0]  # 使用私钥对hash字节流进行加密
    
    print(hash.hex())
    print(encrypted_hash.hex())
    print(abc.hex())
    
    # 使用AES对 消息||加密的哈希值 进行加密
    aes_key = b"0123456789abcdef"
    iv = b"0123456789abcdef"
    aes_obj = AES.new(aes_key, AES.MODE_CBC, iv)  # 面向分组的传输使用CBC加密模式
    padded_plaintext = pad(bytes+encrypted_hash, AES.block_size)
    cypher_text = aes_obj.encrypt(padded_plaintext)
    
    # 密文使用base64编码
    with open(dst_path, 'wb') as f:
        encoded_cypher_text = base64.encodebytes(cypher_text)
        decoded_cypher_text = base64.decodebytes(encoded_cypher_text)
        plaintext = aes_obj.decrypt(decoded_cypher_text)
        print(plaintext.hex())
        # f.write(encoded_cypher_text)

if __name__ == "__main__":
    print(chr(49))
    print(ord('1'))
    # print("开始执行！")
    send("test","111")
    # gen_rsa_key()