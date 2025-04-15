from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64

from encryption_wrapper.src.lib.validate_private_key import validate_private_key


def b64_to_private_key(private_key_b64: str) -> rsa.RSAPrivateKey:
    return validate_private_key(serialization.load_pem_private_key(
        base64.b64decode(private_key_b64),
        password=None,
    ))
