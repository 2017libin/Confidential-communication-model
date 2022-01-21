# Confidential-communication-model

信息系统安全节课作业题目之一：实现如下保密通信模型。其中，(1)表示$E_k[M||E_{SK_A}[H(M)]]$、(2)表示$PK_A$。本项目中使用python库**pycrypto**来实现。代码中使用send2和receive2来表示通信模型2中的发送和接受实体，send3和receive3来表示通信模型3中的发送和接收实体。

1. 通信模型2：
![image-20220121175913269](https://gitee.com/llbd/md-gallery/raw/master/image-20220121175913269.png)

2. 通信模型3：
![image-20220107210905391](https://gitee.com/llbd/md-gallery/raw/master/image-20220107210905391.png)

- 运行环境：python3.8.10 + wls2

- 安装pycrypto：`pip3 install pycrypto`
- 运行：python3 main.py

# 密钥文件后缀
- 证书：cer（windows）或者crt（linux）
- 私钥：key
- base64编码：pem
- 二进制编码：der

# 可能出现的错误
1. 运行gen_rsa_key时报错：
  ```
  File "/home/chase/.local/lib/python3.8/site-packages/Crypto/Random/_UserFriendlyRNG.py", line 77, in collect
    t = time.clock()`
  AttributeError: module 'time' has no attribute 'clock'
  ```
修改该文件中的time.clock()为time.perf_counter()

2. 使用私钥加密，公钥解密时发生错误：
```
TypeError: Private key not available in this object
```
表示在pycrypto库中不支持使用私钥加密，公钥解密。更推荐的做法是使用私钥签名，公钥验签。因此，使用**签名和验签函数**来替换掉原有的**私钥加密/公钥解密函数**。
# 参考链接
- [SSL中，公钥，私钥，证书的后缀名](https://blog.csdn.net/master_yao/article/details/78153933)
- [Python 使用 pycrypto 进行 rsa 公私钥加解密和签名验证](https://wxnacy.com/2018/08/17/python-pycrypto-rsa/)
- [Python Cryptography Toolkit](https://www.dlitz.net/software/pycrypto/doc/)
- [python文件读写](https://www.liaoxuefeng.com/wiki/1016959663602400/1017607179232640)
- [python 报错 AttributeError: module ‘time‘ has no attribute ‘clock 解决方法](https://blog.csdn.net/whatday/article/details/112659677)
- [填充函数pad和unpad](https://www.cjavapy.com/article/243/)
- [decrypt a message with RSA public key with PyCrypto](https://stackoverflow.com/questions/20164397/decrypt-a-message-with-rsa-public-key-with-pycrypto)