from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def load_private_key(file_path: str) -> rsa.RSAPrivateKey:
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    # Validate that it's an RSA private key
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("The provided key is not an RSA private key")

    return private_key