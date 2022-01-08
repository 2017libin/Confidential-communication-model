# Confidential-communication-model

实现如下保密通信模型。其中，(1)表示$E_k[M||E_{SK_A}[H(M)]]$、(2)表示$PK_A$。使用python库**pycrypto**来实现。

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
# 参考链接
- [SSL中，公钥，私钥，证书的后缀名](https://blog.csdn.net/master_yao/article/details/78153933)
- [杂项之python利用pycrypto实现RSA](https://www.cnblogs.com/huxianglin/p/6387045.html)
- [Python Cryptography Toolkit](https://www.dlitz.net/software/pycrypto/doc/)
- [python文件读写](https://www.liaoxuefeng.com/wiki/1016959663602400/1017607179232640)
- [python 报错 AttributeError: module ‘time‘ has no attribute ‘clock 解决方法](https://blog.csdn.net/whatday/article/details/112659677)