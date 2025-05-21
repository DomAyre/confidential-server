from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64

from encryption_wrapper.src.lib.validate_public_key import validate_public_key


def b64_to_public_key(public_key_b64: str) -> rsa.RSAPublicKey:
    return validate_public_key(serialization.load_pem_public_key(
        base64.b64decode(public_key_b64)
    ))
