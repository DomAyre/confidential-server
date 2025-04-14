from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def load_public_key(file_path: str) -> rsa.RSAPublicKey:
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    # Validate that it's an RSA public key
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("The provided key is not an RSA public key")

    return public_key