from cryptography.hazmat.primitives.asymmetric import rsa

def validate_public_key(public_key: rsa.RSAPublicKey) -> rsa.RSAPublicKey:
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("The provided key is not an RSA public key")
    return public_key