import os
import tempfile
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

# Import the module functions to test
from encryption_wrapper.src.generate_keys import generate_key_pair
from encryption_wrapper.src.public_key_to_file import public_key_to_file
from encryption_wrapper.src.private_key_to_file import private_key_to_file
from encryption_wrapper.src.lib.file_to_public_key import file_to_public_key
from encryption_wrapper.src.lib.file_to_private_key import file_to_private_key
from encryption_wrapper.test.utils import run_script


def test_generate_key_pair():
    private_key, public_key = generate_key_pair()
    assert isinstance(private_key, rsa.RSAPrivateKey)
    assert isinstance(public_key, rsa.RSAPublicKey)


def test_key_pair_correspondence():
    private_key, public_key = generate_key_pair()
    assert private_key.public_key() == public_key


def test_script_execution(monkeypatch, tmp_path):
    # Prepare temp file paths
    private_key_path = str(tmp_path / 'test_private.pem')
    public_key_path = str(tmp_path / 'test_public.pem')

    run_script(monkeypatch, " ".join([
        "src/generate_keys.py",
        "--private-key", private_key_path,
        "--public-key", public_key_path,
    ]))

    # Check that files were created
    assert os.path.exists(private_key_path)
    assert os.path.exists(public_key_path)

    # Verify the generated keys can be loaded
    loaded_private_key = file_to_private_key(private_key_path)
    loaded_public_key = file_to_public_key(public_key_path)

    assert isinstance(loaded_private_key, rsa.RSAPrivateKey)
    assert isinstance(loaded_public_key, rsa.RSAPublicKey)