from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode
from base64 import b64encode

BS = 16

TOP_SECRET_KEY = b"TheBestSecureKeyTheBestSecureKey"

def encrypt( data):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(TOP_SECRET_KEY, AES.MODE_CBC, iv)
    return b64encode(iv + cipher.encrypt(pad(data.encode('utf-8'),
                                                  AES.block_size)))


def decrypt( data):
    raw = b64decode(data)
    cipher = AES.new(TOP_SECRET_KEY, AES.MODE_CBC, raw[:AES.block_size])
    return unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size)



