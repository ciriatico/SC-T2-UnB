from math import gcd

class Utils:
    def coprime(a, b):
        return gcd(a, b) == 1
    
    def int_to_bytes(number):
        # Fonte: https://stackoverflow.com/questions/21017698/why-does-bytesn-create-a-length-n-byte-string-instead-of-converting-n-to-a-b
        return number.to_bytes(length=(8 + (number + (number < 0)).bit_length()) // 8, byteorder='big', signed=True)

    def bitwise_xor_bytes(a, b):
        # Fonte: https://techoverflow.net/2020/09/27/how-to-perform-bitwise-boolean-operations-on-bytes-in-python3/
        result_int = int.from_bytes(a, byteorder="big") ^ int.from_bytes(b, byteorder="big")
        return result_int.to_bytes(max(len(a), len(b)), byteorder="big")