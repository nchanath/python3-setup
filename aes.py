#!/usr/bin/env python3

from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

from binascii import hexlify as hexa
from os import urandom

k = urandom(16)  # 128 random bits
print("k = %s" % hexa(k))

cipher = Cipher(
    algorithms.AES(k),
    modes.ECB()
)

aes_encrypt = cipher.encryptor()

p = bytearray(16) # 16 zero bytes
print("p = %s" % hexa(p))

c = aes_encrypt.update(p) + aes_encrypt.finalize()
print("enc(%s) = %s" % (hexa(p), hexa(c)))

aes_decrypt = cipher.decryptor()

p = aes_decrypt.update(c) + aes_decrypt.finalize()
print("dec(%s) = %s" % (hexa(c), hexa(p)))
