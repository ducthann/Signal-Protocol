import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# base64 encoding helper function
def base64_encode(msg):
    return base64.encodebytes(msg).decode('utf-8').strip()

# key derivation function (KDF) based on the HMAC message authentication code
def kdf_HMAC(str, length):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=b'CS594@UIC', info=b'', backend=default_backend()).derive(str)

def padding(msg):
    num = 16 - (len(msg) % 16)
    return msg + bytes([num] * num)

def unpadding(msg):
    return msg[:-msg[-1]]

class Color:
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BRIGHT_RED = '\033[31m'
    BRIGHT_GREEN = '\033[32m'
    BRIGHT_YELLOW = '\033[33m'
    BRIGHT_BLUE = '\033[34m'
    BRIGHT_MAGENTA = '\033[35m'
    BRIGHT_CYAN = '\033[36m'
    END = '\033[0m'