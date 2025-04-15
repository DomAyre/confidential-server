from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64
import argparse
from encryption_wrapper.src.load_public_key import load_public_key


def format_public_key(public_key: rsa.RSAPublicKey) -> str:
    return base64.b64encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).decode('ascii')


def parse_args():
    parser = argparse.ArgumentParser(description='Base64 encode the public key for sending in requests')
    parser.add_argument('--public-key', default="public_key.pem",
                        help='Path where the public key will be saved (default: public_key.pem)')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    public_key = load_public_key(args.public_key)
    formatted_key = format_public_key(public_key)
    print(formatted_key)
