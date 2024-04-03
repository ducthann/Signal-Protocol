import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# base64 encoding helper function
def base64_encode(msg):
    return base64.encodebytes(msg).decode('utf-8').strip()

# key derivation function (KDF) based on the HMAC message authentication code
def kdf_HMAC(str, length):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=b'', info=b'', backend=default_backend()).derive(str)

def padding(msg):
    num = 16 - (len(msg) % 16)
    return msg + bytes([num] * num)

def unpadding(msg):
    return msg[:-msg[-1]]