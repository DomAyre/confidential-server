from argparse import ArgumentParser
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from encryption_wrapper.src.lib.args import add_private_key_arg, add_private_key_b64_arg
from encryption_wrapper.src.lib.b64_to_private_key import b64_to_private_key

def private_key_to_file(private_key: rsa.RSAPrivateKey, private_key_path: str):
    with open(private_key_path, "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )


if __name__ == "__main__":
    parser = ArgumentParser(description="Save a private key to a file")
    add_private_key_b64_arg(parser)
    add_private_key_arg(parser)
    args = parser.parse_args()
    private_key_to_file(b64_to_private_key(args.private_key_b64), args.private_key)
