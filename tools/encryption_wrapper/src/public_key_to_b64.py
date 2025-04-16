from argparse import ArgumentParser
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64

from encryption_wrapper.src.lib.file_to_public_key import file_to_public_key
from encryption_wrapper.src.lib.args import add_public_key_arg

def public_key_to_b64(public_key: rsa.RSAPublicKey) -> str:
    return base64.b64encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).decode('ascii')


if __name__ == "__main__":
    parser = ArgumentParser(description="Convert a public key to base64 format.")
    add_public_key_arg(parser)
    args = parser.parse_args()
    print(public_key_to_b64(file_to_public_key(args.public_key)))
