import os
import base64
import pytest
import tempfile
from cryptography.hazmat.primitives.asymmetric import rsa

from encryption_wrapper.src.generate_keys import generate_key_pair
from encryption_wrapper.src.private_key_to_file import private_key_to_file
from encryption_wrapper.src.private_key_to_b64 import private_key_to_b64
from encryption_wrapper.src.lib.file_to_private_key import file_to_private_key
from encryption_wrapper.src.lib.b64_to_private_key import b64_to_private_key
from encryption_wrapper.test.utils import run_script


def test_private_key_to_file():
    """Test saving a private key to a file and reading it back."""
    private_key, _ = generate_key_pair()

    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        key_path = tmpfile.name

    try:
        # Save private key to file
        private_key_to_file(private_key, key_path)

        # Read it back
        loaded_key = file_to_private_key(key_path)

        # Verify it's a private key
        assert isinstance(loaded_key, rsa.RSAPrivateKey)
        assert loaded_key.key_size == 2048
    finally:
        os.unlink(key_path)


def test_private_key_to_b64():
    """Test converting a private key to base64 and back."""
    private_key, _ = generate_key_pair()

    # Convert to base64
    b64_key = private_key_to_b64(private_key)

    # Verify it's a string
    assert isinstance(b64_key, bytes)  # In the implementation it returns bytes

    # Verify it can be decoded as base64
    try:
        base64.b64decode(b64_key)
    except Exception:
        pytest.fail("Generated base64 string is not valid base64")

    # Convert back to private key
    loaded_key = b64_to_private_key(b64_key)

    # Verify it's a private key
    assert isinstance(loaded_key, rsa.RSAPrivateKey)
    assert loaded_key.key_size == 2048


def test_private_key_conversion_full_cycle():
    """Test a complete cycle of conversions for a private key."""
    original_key, _ = generate_key_pair()

    # Convert to base64
    b64_key = private_key_to_b64(original_key)

    # Convert back to key
    key_from_b64 = b64_to_private_key(b64_key)

    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        key_path = tmpfile.name

    try:
        # Save to file
        private_key_to_file(key_from_b64, key_path)

        # Read from file
        key_from_file = file_to_private_key(key_path)

        # Final verification - should still be a valid private key
        assert isinstance(key_from_file, rsa.RSAPrivateKey)
        assert key_from_file.key_size == 2048

        # Test decryption with the key to ensure functionality is preserved
        test_message = b"test decryption message"
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes

        # Get public key for encryption
        public_key = original_key.public_key()

        # Encrypt with public key
        padding_config = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
        encrypted = public_key.encrypt(test_message, padding_config)

        # Decrypt with original and loaded key
        original_decrypted = original_key.decrypt(encrypted, padding_config)
        loaded_decrypted = key_from_file.decrypt(encrypted, padding_config)

        # Both should decrypt to the original message
        assert original_decrypted == test_message
        assert loaded_decrypted == test_message
    finally:
        os.unlink(key_path)


def test_private_key_to_file_script(monkeypatch, tmp_path):
    """Test the private_key_to_file.py script execution."""
    # Generate a key and get its base64 representation
    private_key, _ = generate_key_pair()
    b64_key = private_key_to_b64(private_key)

    # Prepare temp file path
    private_key_path = str(tmp_path / 'test_private.pem')

    run_script(monkeypatch, " ".join([
        "src/private_key_to_file.py",
        b64_key.decode('utf-8'),  # Convert bytes to string for command line
        '--private-key', private_key_path
    ]))

    # Check that file was created
    assert os.path.exists(private_key_path)

    # Verify the key was saved properly
    loaded_private_key = file_to_private_key(private_key_path)
    assert isinstance(loaded_private_key, rsa.RSAPrivateKey)


def test_private_key_to_b64_script(monkeypatch, tmp_path, capfd):
    """Test the private_key_to_b64.py script execution."""
    # Generate a key pair and save the private key to a file
    private_key, _ = generate_key_pair()
    private_key_path = str(tmp_path / 'script_test_private.pem')
    private_key_to_file(private_key, private_key_path)

    run_script(monkeypatch, " ".join([
        "src/private_key_to_b64.py",
        '--private-key', private_key_path
    ]))

    # Capture the output
    out, _ = capfd.readouterr()
    b64_output = out.strip()

    # Verify output is valid base64
    try:
        decoded = base64.b64decode(b64_output)
    except Exception:
        pytest.fail("Output is not valid base64")

    # Verify we can convert it back to a private key
    loaded_key = b64_to_private_key(b64_output)
    assert isinstance(loaded_key, rsa.RSAPrivateKey)