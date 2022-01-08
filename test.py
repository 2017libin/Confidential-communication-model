#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Author: wxnacy(wxnacy@gmail.com)

from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA
import base64



def signature(message, rsa_path):
    '''使用私钥签名'''
    with open(rsa_path) as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        signer = Signature_pkcs1_v1_5.new(rsakey)
        digest = SHA.new()
        digest.update(message.encode())
        sign = signer.sign(digest)
        signature = sign

        return signature

def verify_signature(message, signature, pub_rsa_path):
    '''验证签名'''
    with open(pub_rsa_path) as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        verifier = Signature_pkcs1_v1_5.new(rsakey)
        digest = SHA.new()
        # Assumes the data is base64 encoded to begin with
        digest.update(message.encode())
        # print(digest)
        is_verify = verifier.verify(digest, signature)
        return is_verify


if __name__ == "__main__":
    plain = 'message'

    sign_pub_rsa_path = 'rsa_pubk.crt'
    sign_rsa_path = 'rsa_pk.key'

    sign = signature(plain, sign_rsa_path)
    print('签名：', sign)
    flag = verify_signature(plain, sign, sign_pub_rsa_path)
    print('验证结果：', flag)