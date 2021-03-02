# xmldsig

https://www.w3.org/Signature/

## 分析

DigestValue是对指定原始内容的摘要

SignedInfo中包含DigestValue

Signature是基于SignedInfo内容生成的签名

注意，SignedInfo预先经过c14n序列化处理

## 签名算法

https://www.w3.org/TR/xmldsig-core/

    <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>

标识使用 RSASSA-PKCS1-v1_5，sha1

## 示例

https://www.di-mgt.com.au/xmldsig.html

https://www.di-mgt.com.au/xmldsig-c14n.html

    $ perl rsa_sha1_verify.pl
    Verified OK
    Signature Verified Successfully
