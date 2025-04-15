import argparse
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

from encryption_wrapper.src.load_private_key import load_private_key


def payload(data: str) -> dict:
    if os.path.isfile(data):
        with open(data, 'r') as f:
            return json.load(f)
    else:
        return json.loads(data)


def decrypt(encrypted_data: dict, private_key: rsa.RSAPrivateKey) -> bytes:

    # Decrypt the AES key with the private RSA key
    encrypted_key = base64.b64decode(encrypted_data["encrypted_key"])
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    iv = base64.b64decode(encrypted_data["iv"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    auth_tag = base64.b64decode(encrypted_data["auth_tag"])

    # Decrypt the data with the AES key
    decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv, auth_tag)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def parse_args():
    parser = argparse.ArgumentParser(description='Decrypt data with private key')
    parser.add_argument('data', type=payload,
                        help='JSON string or path to JSON file containing encrypted data')
    parser.add_argument('--private-key', default="private_key.pem",
                        help='Path to the private key file (default: private_key.pem)')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    print(decrypt(args.data, load_private_key(args.private_key)).decode())
