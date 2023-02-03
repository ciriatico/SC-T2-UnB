from math import ceil
import os
import hashlib
from hashlib import sha3_256
from utils import Utils
from rsa import RSA

class OAEP:
    # Implementação baseada em: https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
    def sha1(m):
        hasher = hashlib.sha1()
        hasher.update(m)

        return hasher.digest()

    def mgf1(seed, mlen):
        # Implementação baseada em: https://en.wikipedia.org/wiki/Mask_generation_function
        t = b''
        hlen = len(OAEP.sha1(b''))
        for c in range(ceil(mlen / hlen)):
            _c = c.to_bytes(4, byteorder='big')
            t += OAEP.sha1(seed + _c)

        return t[:mlen]
    
    def encrypt_oaep(m, public_key):
        hlen = 20
        k = public_key[1].bit_length() // 8

        return RSA.enc_rsa(int.from_bytes(OAEP.oaep_encode(m, k), byteorder='big'), public_key)

    def oaep_encode(m, k, label=b''):
        bm = m
        mlen = len(bm)
        lhash = OAEP.sha1(label)
        hlen = len(lhash)

        ps = b'\x00' * (k - mlen - 2 * hlen - 2)
        db = lhash + ps + b'\x01' + bm
        seed = os.urandom(hlen)
        db_mask = OAEP.mgf1(seed, k - hlen - 1)
        masked_db = Utils.bitwise_xor_bytes(db, db_mask)
        seed_mask = OAEP.mgf1(masked_db, hlen)
        masked_seed = Utils.bitwise_xor_bytes(seed, seed_mask)

        return b'\x00' + masked_seed + masked_db
    
    def decrypt_oaep(c, private_key):
        k = private_key[1].bit_length() // 8
        hlen = 20
        return OAEP.oaep_decode(RSA.dec_rsa(c, private_key).to_bytes(k, byteorder='big'), k)

    def oaep_decode(c, k, label=b''):
        lhash = OAEP.sha1(label)
        hlen = len(lhash)

        _, masked_seed, masked_db = c[:1], c[1:1 + hlen], c[1 + hlen:]
        seed_mask = OAEP.mgf1(masked_db, hlen)
        seed = Utils.bitwise_xor_bytes(masked_seed, seed_mask)
        db_mask = OAEP.mgf1(seed, k - hlen - 1)
        db = Utils.bitwise_xor_bytes(masked_db, db_mask)
        i = hlen
        
        while i < len(db):
            if db[i] == 0:
                i += 1
                continue
            elif db[i] == 1:
                i += 1
                break

        m = db[i:]
        
        return m