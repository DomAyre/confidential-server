from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import argparse


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem


def save_key_pair(private_pem, public_pem, private_file="private_key.pem", public_file="public_key.pem"):
    with open(private_file, "wb") as priv_file:
        priv_file.write(private_pem)
    with open(public_file, "wb") as pub_file:
        pub_file.write(public_pem)


def parse_args():
    parser = argparse.ArgumentParser(description='Generate RSA key pair')
    parser.add_argument('--private-key', default="private_key.pem",
                        help='Path where the private key will be saved (default: private_key.pem)')
    parser.add_argument('--public-key', default="public_key.pem",
                        help='Path where the public key will be saved (default: public_key.pem)')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    private_pem, public_pem = generate_key_pair()
    save_key_pair(private_pem, public_pem, args.private_key, args.public_key)