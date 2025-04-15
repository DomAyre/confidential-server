import argparse
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

from encryption_wrapper.src.load_public_key import load_public_key
from encryption_wrapper.src.lib.zip_directory import zip_directory


def payload(data: str) -> bytes:
    if os.path.exists(data):
        if os.path.isdir(data):
            # print(f"Encrypting directory: {data}")
            return zip_directory(data)
        elif os.path.isfile(data):
            # print(f"Encrypting file: {data}")
            with open(data, 'rb') as file:
                return file.read()
    else:
        # print(f"Encrypting: \"{data}\"")
        return data.encode()


def encrypt(data: bytes, public_key: rsa.RSAPublicKey) -> dict:

    # Create a symmetric AES key and encrypt it with the public RSA key
    aes_key = os.urandom(32)
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Encrypt the data with the AES key
    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    return {
        "encrypted_key": base64.b64encode(encrypted_key).decode('utf-8'),
        "iv": base64.b64encode(iv).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "auth_tag": base64.b64encode(encryptor.tag).decode('utf-8')
    }

def parse_args():
    parser = argparse.ArgumentParser(description='Encrypt data with public key')
    parser.add_argument('data', type=payload,
                        help='Either a path to be encrypted, or the raw data')
    parser.add_argument('--public-key', default="public_key.pem",
                        help='Path where the public key will be saved (default: public_key.pem)')
    return parser.parse_args()

if __name__  == "__main__":
    args = parse_args()
    print(json.dumps(encrypt(args.data, load_public_key(args.public_key))))
