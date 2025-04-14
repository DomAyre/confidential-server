from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64
import argparse


def parse_public_key(public_key_b64: str) -> rsa.RSAPublicKey:
    try:
        pem_data = base64.b64decode(public_key_b64)
    except Exception as e:
        raise ValueError(f"Invalid base64 encoded public key: {e}")

    # Load the PEM formatted public key
    try:
        public_key = serialization.load_pem_public_key(pem_data)
    except Exception as e:
        raise ValueError(f"Invalid PEM format public key: {e}")

    # Validate that it's an RSA public key
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("The provided key is not an RSA public key")

    return public_key


def save_public_key(public_key: rsa.RSAPublicKey, public_key_path: str):
    with open(public_key_path, "wb") as key_file:
        key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))


def parse_args():
    parser = argparse.ArgumentParser(description='Base64 encode the public key for sending in requests')
    parser.add_argument('--public-key', default="public_key.pem",
                        help='Path where the public key will be saved (default: public_key.pem)')
    parser.add_argument('--public-key-b64', help='The base64 encoded public key')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    save_public_key(parse_public_key(args.public_key_b64), args.public_key)
