from argparse import ArgumentParser
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from encryption_wrapper.src.lib.args import add_public_key_arg, add_public_key_b64_arg
from encryption_wrapper.src.lib.b64_to_public_key import b64_to_public_key


def public_key_to_file(public_key: rsa.RSAPublicKey, public_key_path: str):
    with open(public_key_path, "wb") as key_file:
        key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))


if __name__ == "__main__":
    parser = ArgumentParser(description="Save a public key to a file")
    add_public_key_b64_arg(parser)
    add_public_key_arg(parser)
    args = parser.parse_args()
    public_key_to_file(b64_to_public_key(args.public_key_b64), args.public_key)
