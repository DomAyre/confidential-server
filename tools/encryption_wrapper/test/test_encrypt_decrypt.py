import json
import os
import tempfile
from pathlib import Path

from encryption_wrapper.src.generate_keys import generate_key_pair
from encryption_wrapper.src.encrypt import encrypt, payload
from encryption_wrapper.src.decrypt import decrypt
from encryption_wrapper.test.utils import run_script


def test_encrypt_decrypt_string():
    """Test encrypting and decrypting a string."""
    # Generate key pair
    private_key, public_key = generate_key_pair()

    # Test data
    test_data = "This is a test string"

    # Prepare data as bytes (as the payload function would do)
    data_bytes = test_data.encode()

    # Encrypt
    encrypted = encrypt(data_bytes, public_key)

    # Verify encrypted data structure
    assert "encrypted_key" in encrypted
    assert "iv" in encrypted
    assert "ciphertext" in encrypted
    assert "auth_tag" in encrypted

    # Decrypt
    decrypted = decrypt(encrypted, private_key)

    # Verify decryption was successful
    assert decrypted == data_bytes
    assert decrypted.decode() == test_data


def test_encrypt_decrypt_file():
    """Test encrypting and decrypting a file."""
    # Generate key pair
    private_key, public_key = generate_key_pair()

    # Create a temporary file with test content
    with tempfile.NamedTemporaryFile(delete=False, mode='w') as tmp:
        tmp.write("Test file content")
        tmp_path = tmp.name

    try:
        # Get file content as bytes using the payload function
        file_bytes = payload(tmp_path)

        # Encrypt
        encrypted = encrypt(file_bytes, public_key)

        # Decrypt
        decrypted = decrypt(encrypted, private_key)

        # Verify decryption was successful
        with open(tmp_path, 'rb') as f:
            assert decrypted == f.read()
    finally:
        os.unlink(tmp_path)


def test_encrypt_decrypt_directory():
    """Test encrypting and decrypting a directory."""
    # Generate key pair
    private_key, public_key = generate_key_pair()

    # Create a temporary directory with some files
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create some files in the directory
        for i in range(3):
            with open(os.path.join(tmpdir, f"test_file_{i}.txt"), 'w') as f:
                f.write(f"Content of test file {i}")

        # Create a subdirectory with files
        subdir = os.path.join(tmpdir, "subdir")
        os.makedirs(subdir)
        for i in range(2):
            with open(os.path.join(subdir, f"subdir_file_{i}.txt"), 'w') as f:
                f.write(f"Content of subdir file {i}")

        # Get directory content as bytes using the payload function
        dir_bytes = payload(tmpdir)

        # Encrypt
        encrypted = encrypt(dir_bytes, public_key)

        # Decrypt
        decrypted = decrypt(encrypted, private_key)

        # Verify we got a zip file back (we can't directly compare with the original
        # directory, but we can verify it's a valid zip file)
        import zipfile
        import io

        zip_bytes = io.BytesIO(decrypted)
        with zipfile.ZipFile(zip_bytes) as zip_file:
            # Check the zip file contains the expected files
            file_list = zip_file.namelist()
            assert "test_file_0.txt" in file_list
            assert "test_file_1.txt" in file_list
            assert "test_file_2.txt" in file_list
            assert "subdir/subdir_file_0.txt" in file_list
            assert "subdir/subdir_file_1.txt" in file_list

            # Check the content of a file in the zip
            with zip_file.open("test_file_0.txt") as f:
                assert f.read().decode() == "Content of test file 0"


def test_payload_string():
    """Test the payload function with a string."""
    test_string = "Test string data"
    result = payload(test_string)
    assert result == test_string.encode()


def test_payload_file():
    """Test the payload function with a file."""
    with tempfile.NamedTemporaryFile(delete=False, mode='w') as tmp:
        content = "Test file content"
        tmp.write(content)
        tmp_path = tmp.name

    try:
        result = payload(tmp_path)
        assert result == content.encode()
    finally:
        os.unlink(tmp_path)


def test_payload_directory():
    """Test the payload function with a directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create some files in the directory
        for i in range(2):
            with open(os.path.join(tmpdir, f"test_{i}.txt"), 'w') as f:
                f.write(f"Content {i}")

        # Get directory content as bytes
        result = payload(tmpdir)

        # Verify it's a valid zip file
        import zipfile
        import io

        zip_bytes = io.BytesIO(result)
        with zipfile.ZipFile(zip_bytes) as zip_file:
            file_list = zip_file.namelist()
            assert "test_0.txt" in file_list
            assert "test_1.txt" in file_list


def test_encrypt_script(monkeypatch, tmp_path, capfd):
    """Test the encrypt.py script execution."""
    # Generate key pair and save the public key to a file
    private_key, public_key = generate_key_pair()
    public_key_path = str(tmp_path / 'test_public.pem')

    from encryption_wrapper.src.public_key_to_file import public_key_to_file
    public_key_to_file(public_key, public_key_path)

    # Create a temporary file with test content
    test_file = str(tmp_path / 'test_content.txt')
    test_content = "Hello, world!"
    with open(test_file, 'w') as f:
        f.write(test_content)

    run_script(monkeypatch, " ".join([
        "src/encrypt.py",
        test_file,
        "--public-key", public_key_path,
    ]))

    # Capture the output
    out, _ = capfd.readouterr()

    # Parse the JSON output
    encrypted_data = json.loads(out)

    # Verify the structure of the encrypted data
    assert "encrypted_key" in encrypted_data
    assert "iv" in encrypted_data
    assert "ciphertext" in encrypted_data
    assert "auth_tag" in encrypted_data

    # Decrypt the data and verify it matches the original
    decrypted = decrypt(encrypted_data, private_key)
    assert decrypted.decode() == test_content


def test_decrypt_script(monkeypatch, tmp_path):
    """Test the decrypt.py script execution."""
    # Generate key pair and save the private key to a file
    private_key, public_key = generate_key_pair()
    private_key_path = str(tmp_path / 'test_private.pem')

    from encryption_wrapper.src.private_key_to_file import private_key_to_file
    private_key_to_file(private_key, private_key_path)

    # Encrypt some test data
    test_content = "Test decryption content"
    encrypted_data = encrypt(test_content.encode(), public_key)

    # Save encrypted data to a file
    encrypted_file = str(tmp_path / 'encrypted.json')
    with open(encrypted_file, 'w') as f:
        json.dump(encrypted_data, f)

    # Prepare output file
    output_file = str(tmp_path / 'decrypted.txt')

    run_script(monkeypatch, " ".join([
        "src/decrypt.py",
        encrypted_file,
        '--private-key', private_key_path,
        '--out', output_file
    ]))

    # Verify the output file was created and contains the correct content
    assert Path(output_file).exists()
    with open(output_file, 'r') as f:
        decrypted_content = f.read()

    assert decrypted_content == test_content