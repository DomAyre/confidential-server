from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64
import argparse
from encryption_wrapper.src.load_private_key import load_private_key


def format_private_key(private_key: rsa.RSAPrivateKey) -> str:
    return base64.b64encode(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('ascii')
    )


def parse_args():
    parser = argparse.ArgumentParser(description='Base64 encode the private key for sending in requests')
    parser.add_argument('--private-key', default="private_key.pem",
                        help='Path where the private key will be saved (default: private_key.pem)')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    private_key = load_private_key(args.private_key)
    formatted_key = format_private_key(private_key)
    print(formatted_key)
