from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import argparse

from encryption_wrapper.src.lib.args import add_private_key_arg, add_public_key_arg
from encryption_wrapper.src.private_key_to_file import private_key_to_file
from encryption_wrapper.src.public_key_to_file import public_key_to_file


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key, private_key.public_key()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate RSA key pair')
    add_public_key_arg(parser)
    add_private_key_arg(parser)
    args = parser.parse_args()

    private_key, public_key = generate_key_pair()
    private_key_to_file(private_key, args.private_key)
    public_key_to_file(public_key, args.public_key)
