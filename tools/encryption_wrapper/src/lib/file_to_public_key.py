from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from encryption_wrapper.src.lib.validate_public_key import validate_public_key

def file_to_public_key(file_path: str) -> rsa.RSAPublicKey:
    with open(file_path, "rb") as key_file:
        return validate_public_key(
            serialization.load_pem_public_key(key_file.read())
        )
