from argparse import ArgumentParser
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64

from encryption_wrapper.src.lib.args import add_private_key_arg
from encryption_wrapper.src.lib.file_to_private_key import file_to_private_key


def private_key_to_b64(private_key: rsa.RSAPrivateKey) -> bytes:
    return base64.b64encode(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )


if __name__ == "__main__":
    parser = ArgumentParser(description="Convert a private key to base64 format.")
    add_private_key_arg(parser)
    args = parser.parse_args()
    print(private_key_to_b64(file_to_private_key(args.private_key)).decode())
