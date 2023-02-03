from hashlib import sha3_256
from rsa import RSA

class Signature:
    def get_signature(data, public_key):
        hashed = sha3_256(data).digest()

        return RSA.enc_rsa(int.from_bytes(hashed, "big"), public_key)

    def check_signature(assinatura, data, private_key):
        hashed = sha3_256(data).digest()

        return RSA.dec_rsa(int.from_bytes(assinatura, "big"), private_key) == int.from_bytes(hashed, "big")