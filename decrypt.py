import hashlib
import base64
import os
import sys
import zlib
import hmac

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

def _decrypt_password(enc_pw, secret, salt):
    nonce = enc_pw[:32]
    ct = enc_pw[32:]
    key = _derive_key(secret, salt, b'\x00')
    ks = _keystream(key, nonce, len(ct))
    return _xor(ct, ks)

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
    data = bytes(inv2[b] for b in data)
    data = _xor(data, _keystream(keys[4], nonce, len(data)))
    data = _permute(data, keys[3], nonce, False)
    data = _rotate(data, keys[2], nonce, -1)
    data = _xor(data, _keystream(keys[1], nonce, len(data)))
    sbox1 = _build_sbox(keys[0])
    inv1 = [0] * 256
    for i in range(256):
        inv1[sbox1[i]] = i
    data = bytes(inv1[b] for b in data)
    return zlib.decompress(data)

def main():
    target = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'kitty_checker.py')
    with open(target, 'r', encoding='utf-8') as f:
        source = f.read()

    if 'bytes.fromhex' not in source or '_b.b64decode(' not in source:
        if "_p=b'" in source:
            print("File uses old encryption format (plaintext password). Re-encrypt with new encrypter first.")
        else:
            print("File is not encrypted.")
        sys.exit(0)

    hex_positions = []
    search_from = 0
    while True:
        pos = source.find('bytes.fromhex("', search_from)
        if pos == -1:
            break
        start = pos + len('bytes.fromhex("')
        end = source.index('")', start)
        hex_positions.append((start, end))
        search_from = end + 2

    if len(hex_positions) < 4:
        print("File is not encrypted or uses old format.")
        sys.exit(0)

    salt = bytes.fromhex(source[hex_positions[0][0]:hex_positions[0][1]])
    masked = bytes.fromhex(source[hex_positions[1][0]:hex_positions[1][1]])
    mask = bytes.fromhex(source[hex_positions[2][0]:hex_positions[2][1]])
    enc_pw = bytes.fromhex(source[hex_positions[3][0]:hex_positions[3][1]])

    secret = bytes(a ^ b for a, b in zip(masked, mask))
    password = _decrypt_password(enc_pw, secret, salt)

    blob_start = source.index('_b.b64decode("') + len('_b.b64decode("')
    blob_end = source.index('")', blob_start)
    blob = source[blob_start:blob_end]

    encrypted = base64.b64decode(blob)
    original = _decrypt(encrypted, password, salt).decode('utf-8')

    with open(target, 'w', encoding='utf-8') as f:
        f.write(original)

    print(f"Decrypted {len(blob)} base64 chars -> {len(original)} bytes")
    print(f"HMAC: verified")
    print(f"Password: recovered from encrypted store")
    print("Decryption complete.")

if __name__ == '__main__':
    main()
