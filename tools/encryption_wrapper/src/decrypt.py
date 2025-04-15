import argparse
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

from encryption_wrapper.src.lib.file_to_private_key import file_to_private_key
from encryption_wrapper.src.lib.args import add_private_key_arg


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

    # Decrypt the data with the AES key
    iv = base64.b64decode(encrypted_data["iv"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    auth_tag = base64.b64decode(encrypted_data["auth_tag"])
    decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv, auth_tag)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Decrypt data with private key')
    parser.add_argument('data', type=payload,
                        help='JSON string or path to JSON file containing encrypted data')
    add_private_key_arg(parser)
    args = parser.parse_args()

    print(decrypt(args.data, file_to_private_key(args.private_key)).decode())
