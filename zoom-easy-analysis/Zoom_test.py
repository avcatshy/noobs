import os, base64 
import uuid,random
import subprocess
import hashlib
from urllib.parse import quote
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher

PASSWD_KEY=""
DEVICE_ID=""
__BLOCK_SIZE_16 = BLOCK_SIZE_16 = AES.block_size

# 第一次启动app的时候，使用这种方式生成id，存入keychain
def gen_identifier(bundleid):
    _str=str(uuid.uuid1())+bundleid
    _out=hashlib.sha256(_str.encode()).hexdigest()
    print (_out)
    DEVICE_ID=_out
    return _out

#  这个identifier 是可以直接从keychain 中读取的， 利用keychain_dumper 或 frida 
# 从keychain 中读取64 位字符的id当作字符串传入即可
def compute_hash_macaddress(identifier):
    if isinstance(identifier, str):
        identifier = identifier.encode()
    # identifier=bytes.fromhex(identifier)
    a=hashlib.sha256(identifier).hexdigest()
    b=hashlib.sha256(bytes.fromhex(a)).hexdigest()
    c=hashlib.sha256(bytes.fromhex(b)).hexdigest()
    result=base64.b64encode(bytes.fromhex(c))
    print (result)
    return result

# AES 加密， 
# 计算ecp 字段 直接取一个udid做key， 
# 计算passwd字段，就是将计算session_key时生成的sha256 转成byte[]当作key，加密password即可
# 将key的sha256当作aes的key，sha256(aes_key)做为iv值

def AES_enc(_key, _passwd):
    if isinstance(_key, str):
        _key=_key.encode('utf-8')
    _aes_key=hashlib.sha256(_key).hexdigest()
    # print (_aes_key)
    _aes_iv=hashlib.sha256(bytes.fromhex(_aes_key)).hexdigest()
    # print (_aes_iv)
    cipher=AES.new(bytes.fromhex(_aes_key)[0:16], AES.MODE_CBC,bytes.fromhex(_aes_iv)[0:16])
    x=__BLOCK_SIZE_16 - (len(_passwd) % __BLOCK_SIZE_16)
    if x!=0:
        _passwd=_passwd+chr(x)*x
    _enc = cipher.encrypt(_passwd)
    _out=base64.b64encode(_enc)
    print(_out)
    return _out
        
# pyOpenSSL中没有提供evp加密相关gn，
# 由于rsa部分不好测试，故对照反汇编代码使用cpp实现此部分功能        
def openssl_rsa_enc(data):
    process = os.popen("./RSA %s"%data)
    output = process.read()
    # print(output)
    process.close()
    return bytes.fromhex(output)

def RSA_enc():
    a=compute_hash_macaddress(DEVICE_ID)
    # b=random.randbytes(32)
    b = bytes([random.randrange(0, 256) for _ in range(0, 32)])
    _in=a+b
    # print ("_in:", _in, type(_in))
    c=hashlib.sha256(_in).hexdigest() # 记住这个sha256 的值
    PASSWD_KEY=c
    print (c)
    _rsa_encd=openssl_rsa_enc(c)
    _out=base64.b64encode(_rsa_encd)
    _out=_out+b',v1'
    _out=quote(_out.decode())
    print(_out)


# read from keychain
print ("\n=====gen_identifier====")
_bundle_id="us.zoom.videomeetings"
_ident=gen_identifier(_bundle_id)
print ("\n====hash_macaddress====")
compute_hash_macaddress(_ident)
print ("\n====ecp====")
AES_enc(str(uuid.uuid1()), "password")
print ("\n======ZM-SESS-KEY====")
RSA_enc()
print ("\n====passwd====")
print ("key is:sha256(hash_macaddress+random(32))")
AES_enc(bytes.fromhex(PASSWD_KEY), "password")

