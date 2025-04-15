from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64
import argparse


def parse_private_key(private_key_b64: str) -> rsa.RSAPrivateKey:
    try:
        pem_data = base64.b64decode(private_key_b64)
    except Exception as e:
        raise ValueError(f"Invalid base64 encoded private key: {e}")

    # Load the PEM formatted private key
    try:
        private_key = serialization.load_pem_private_key(pem_data)
    except Exception as e:
        raise ValueError(f"Invalid PEM format private key: {e}")

    # Validate that it's an RSA private key
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("The provided key is not an RSA private key")

    return private_key


def save_private_key(private_key: rsa.RSAPrivateKey, private_key_path: str):
    with open(private_key_path, "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )


def parse_args():
    parser = argparse.ArgumentParser(description='Base64 encode the private key for sending in requests')
    parser.add_argument('--private-key', default="private_key.pem",
                        help='Path where the private key will be saved (default: private_key.pem)')
    parser.add_argument('--private-key-b64', help='The base64 encoded private key')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    save_private_key(parse_private_key(args.private_key_b64), args.private_key)
