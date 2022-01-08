from os import openpty
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Signature import PKCS1_v1_5
# 以字节流的形式返回文件内容
def read_file_by_byte(filename:str):
    f = open(filename, 'rb+')
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
def send(filename:str):
    bytes = read_file_by_byte(filename)  # 以字节的形式返回文件内容

    # 计算文件的哈希值
    md = SHA256.new()
    md.update(bytes)
    hash = md.hexdigest()  # 返回16进制的字符串
    print(type(hash))
    
    # 对哈希值进行签名
    with open("rsa_pk.key","r") as f:
        rsa_pk = RSA.importKey(f.read())
    rng = Random.new().read
    

if __name__ == "__main__":
    # print("开始执行！")
    send("test")
    # gen_rsa_key()