import os
import base64
import pytest
import tempfile
from cryptography.hazmat.primitives.asymmetric import rsa

from encryption_wrapper.src.generate_keys import generate_key_pair
from encryption_wrapper.src.public_key_to_file import public_key_to_file
from encryption_wrapper.src.public_key_to_b64 import public_key_to_b64
from encryption_wrapper.src.lib.file_to_public_key import file_to_public_key
from encryption_wrapper.src.lib.b64_to_public_key import b64_to_public_key
from encryption_wrapper.test.utils import run_script


def test_public_key_to_file():
    _, public_key = generate_key_pair()

    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        key_path = tmpfile.name

    try:
        # Save public key to file then read it back
        public_key_to_file(public_key, key_path)
        loaded_key = file_to_public_key(key_path)

        # Verify it's a public key
        assert isinstance(loaded_key, rsa.RSAPublicKey)
        assert loaded_key.key_size == 2048
    finally:
        os.unlink(key_path)


def test_public_key_to_b64():
    _, public_key = generate_key_pair()

    # Convert to base64 and attempt to decode
    b64_key = public_key_to_b64(public_key)
    try:
        base64.b64decode(b64_key)
    except Exception:
        pytest.fail("Generated base64 string is not valid base64")

    loaded_key = b64_to_public_key(b64_key)
    assert isinstance(loaded_key, rsa.RSAPublicKey)
    assert loaded_key.key_size == 2048


def test_public_key_conversion_full_cycle():
    _, original_key = generate_key_pair()

    b64_key = public_key_to_b64(original_key)
    key_from_b64 = b64_to_public_key(b64_key)

    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        key_path = tmpfile.name

    try:
        public_key_to_file(key_from_b64, key_path)
        key_from_file = file_to_public_key(key_path)

        assert isinstance(key_from_file, rsa.RSAPublicKey)
        assert key_from_file.key_size == 2048

        # Test encryption with the key to ensure functionality is preserved
        test_message = b"test message"
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes

        padding_config = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
        original_encrypted = original_key.encrypt(test_message, padding_config)

        file_encrypted = key_from_file.encrypt(test_message, padding_config)

        assert len(original_encrypted) == len(file_encrypted)
    finally:
        os.unlink(key_path)


def test_public_key_to_file_script(monkeypatch, tmp_path):
    _, public_key = generate_key_pair()
    b64_key = public_key_to_b64(public_key)

    public_key_path = str(tmp_path / 'test_public.pem')

    run_script(monkeypatch, " ".join([
        "src/public_key_to_file.py",
        b64_key,
        '--public-key', public_key_path
    ]))

    assert os.path.exists(public_key_path)

    loaded_public_key = file_to_public_key(public_key_path)
    assert isinstance(loaded_public_key, rsa.RSAPublicKey)


def test_public_key_to_b64_script(monkeypatch, tmp_path, capfd):
    _, public_key = generate_key_pair()
    public_key_path = str(tmp_path / 'script_test_public.pem')
    public_key_to_file(public_key, public_key_path)

    run_script(monkeypatch, " ".join([
        "src/public_key_to_b64.py",
        '--public-key', public_key_path
    ]))

    # Capture the output
    out, _ = capfd.readouterr()
    b64_output = out.strip()

    # Verify output is valid base64
    try:
        base64.b64decode(b64_output)
    except Exception:
        pytest.fail("Output is not valid base64")

    loaded_key = b64_to_public_key(b64_output)
    assert isinstance(loaded_key, rsa.RSAPublicKey)