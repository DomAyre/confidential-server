from cryptography.hazmat.primitives.asymmetric import rsa

def validate_private_key(private_key: rsa.RSAPrivateKey) -> rsa.RSAPrivateKey:
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("The provided key is not an RSA private key")
    return private_key