from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_key_pair():
    """Generates a PEM-encoded RSA public-private key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def save_key_pair(private_pem, public_pem, private_file="private_key.pem", public_file="public_key.pem"):
    """Saves the PEM-encoded keys to files."""
    with open(private_file, "wb") as priv_file:
        priv_file.write(private_pem)
    with open(public_file, "wb") as pub_file:
        pub_file.write(public_pem)

if __name__ == "__main__":
    save_key_pair(*generate_key_pair())