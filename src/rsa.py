import random
from utils import Utils

class RSA:
    def miller_rabin_test(n, k=40):
        # Implementação baseada em: https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Primality_Testing
        n_um = n - 1
        i = 1

        while True:
            if (n-1) % i != 0:
                break

            s = i
            d = n_um//(2**i)
            i += 1

        for j in range(0, k):
            break_nested = False

            a = random.randrange(2, n-2)
            x = pow(a, d, n)

            if (x == 1) or (x == n_um):
                continue

            for r in range(s-1):
                x = pow(x, 2, n)

                if x == n_um:
                    break

            else:
                return False

        return True

    def get_prime(bits):
        p = random.getrandbits(bits)

        while True:
            if RSA.miller_rabin_test(p):
                return p

            p = random.getrandbits(bits)
    
    def get_keys():
        p = RSA.get_prime(1024)
        q = RSA.get_prime(1024)

        while p == q:
            p = get_prime(1024)
            q = get_prime(1024)

        n = p*q
        phi = (p-1)*(q-1)

        e = random.randint(2, phi-1)

        while (not Utils.coprime(e, n)) or (not Utils.coprime(e, phi)):
            e = random.randint(2, phi-1)

        d = pow(e, -1, phi)

        key = {
            'p': p,
            'q': q,
            'public': (e, n),
            'private': (d, n)
        }

        return key
    
    def enc_rsa(m, public_key):
        e = public_key[0]
        n = public_key[1]

        return pow(m, e, n)
    
    def dec_rsa(c, private_key):
        d = private_key[0]
        n = private_key[1]

        return pow(c, d, n)