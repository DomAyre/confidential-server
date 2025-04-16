import argparse


def add_public_key_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--public-key",
        default="public_key.pem",
        help="Path to the public key file used for encryption.",
    )


def add_private_key_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--private-key",
        default="private_key.pem",
        help="Path to the private key file used for decryption.",
    )


def add_public_key_b64_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "public_key_b64",
        help="Base64 encoded representation of the public key",
    )


def add_private_key_b64_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "private_key_b64",
        help="Base64 encoded representation of the private key",
    )
