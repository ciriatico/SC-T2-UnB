import base64
import argparse
from rsa import RSA
from oaep import OAEP
from utils import Utils
from signature import Signature

parser = argparse.ArgumentParser(description='Encryption, decryption and signature of files using RSA combined with OAEP.')
parser.add_argument('-s', dest='source', type=str, default=None, help='Path to the source file, which will be encrypted.')
parser.add_argument('-o', dest='output', type=str, default=None, help='Path to the output file, with the encrypted message.')
parser_opt = parser.parse_args()

source_file = parser_opt.source
output_file = parser_opt.output

keys = RSA.get_keys()

print("p: ", keys["p"])
print("q: ", keys["q"])
print()
print("Chave pública: ", keys["public"])
print("Chave privada: ", keys["private"])
print()

with open(source_file, "rb") as f:
    msg = f.read()

msg_cifrada = OAEP.encrypt_oaep(msg, keys['public'])

print("Mensagem: ", msg)
print("Mensagem cifrada: ", Utils.int_to_bytes(msg_cifrada))
print()

with open(output_file, "wb") as f:
    f.write(Utils.int_to_bytes(msg_cifrada))

assinatura = Signature.get_signature(msg, keys['public'])
assinatura = base64.b64encode(Utils.int_to_bytes(assinatura)).decode("ascii")

print("Assinatura: ", assinatura)
print()

with open(output_file, "rb") as f:
    msg_cifrada = f.read()

msg_decifrada = OAEP.decrypt_oaep(int.from_bytes(msg_cifrada, "big"), keys['private'])

print("Mensagem decifrada: ", msg_decifrada)

assinatura = base64.b64decode(assinatura)

checked_signature = Signature.check_signature(assinatura, msg_decifrada, keys['private'])

print()

if checked_signature:
    print("Assinatura válida")
else:
    print("Assinatura inválida")