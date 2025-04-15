from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from encryption_wrapper.src.lib.validate_private_key import validate_private_key

def file_to_private_key(file_path: str) -> rsa.RSAPrivateKey:
    with open(file_path, "rb") as key_file:
        return validate_private_key(
            serialization.load_pem_private_key(key_file.read(), password=None)
        )
