from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import scrypt
import base64
import json
import argparse


def enc(message, password, k_len, file):
    salt = get_random_bytes(16)
    msg = message.encode('utf-8')
    
    key = scrypt(password, salt, k_len, N = 2**14, r = 16, p = 1)
    
    cipher = AES.new(key, AES.MODE_CBC)
    ciphered_data = cipher.encrypt(pad(msg, AES.block_size))

    
    data_salt = base64.b64encode(salt)
    salt_string = data_salt.decode('ascii')

    iv = base64.b64encode(cipher.iv)
    iv_string = iv.decode('ascii')

    data_cipher = base64.b64encode(ciphered_data)
    string_ciphered_data = data_cipher.decode('ascii')

    data = {
        'salt':salt_string,
        'iv':iv_string,
        'ciphered_data':string_ciphered_data
        }

    s = json.dumps(data)
    with open(file, 'w') as f:
        f.write(s)
    with open(file, 'r') as f:
        jsondata = f.read()

    obj = json.loads(jsondata)
    print("Encryption result:")
    print(obj)

def dec(password, k_len, file):
    with open(file, 'r') as f:
        jsondata = f.read()

    obj = json.loads(jsondata)

    salt_string = obj['salt']
    encoded_salt = salt_string.encode('utf-8')
    salt = base64.b64decode(encoded_salt)

    iv_string = obj['iv']
    encoded_iv = iv_string.encode('utf-8')
    iv = base64.b64decode(encoded_iv)

    string_ciphered_data = obj['ciphered_data']
    encoded_ciphered_data = string_ciphered_data.encode('utf-8')
    ciphered_data = base64.b64decode(encoded_ciphered_data)

    key = scrypt(password, salt, k_len, N = 2**14, r = 16, p = 1)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    original = unpad(cipher.decrypt(ciphered_data), AES.block_size)
    print("Plaintext:")
    print(original.decode('ascii'))


parser = argparse.ArgumentParser()

parser.add_argument('func')
parser.add_argument('-m')
parser.add_argument('-p')
parser.add_argument('-k', type=int)
parser.add_argument('-f')
args = parser.parse_args()

if args.func == "enc":
    enc(args.m, args.p, args.k, args.f)
elif args.func == "dec":
    dec(args.p, args.k, args.f)
else:
    print("Wrong Format")


