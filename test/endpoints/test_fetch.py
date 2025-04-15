from argparse import Namespace
import json
import os
from config.parser import parse_config_file
from encryption_wrapper.src.decrypt import decrypt
from lib.zip_directory import zip_directory
from server.run import create_app
from encryption_wrapper.src.generate_keys import generate_key_pair
from encryption_wrapper.src.format_public_key import format_public_key
import zipfile
import io

def get_test_client(config_path):
    return create_app(args=Namespace(
        config=parse_config_file(config_path),
    )).test_client()


def test_requesting_file_in_config():
    private_key, public_key = generate_key_pair()
    server = get_test_client("examples/config/single_file_single_policy.yml")
    response = server.post('/fetch/readme.md', json={'wrapping_key': format_public_key(public_key)})
    assert response.status_code == 200
    with open("readme.md", "rb") as expected:
        assert expected.read() == decrypt(response.json, private_key)


def test_posting_file_which_doesnt_exist():
    private_key, public_key = generate_key_pair()
    server = get_test_client("examples/config/single_file_single_policy.yml")
    response = server.post('/fetch/doesnt_exist.md', json={'wrapping_key': format_public_key(public_key)})
    assert response.status_code == 404


def test_posting_file_not_in_config():
    private_key, public_key = generate_key_pair()
    server = get_test_client("examples/config/single_file_single_policy.yml")
    response = server.post('/fetch/license', json={'wrapping_key': format_public_key(public_key)})
    assert response.status_code == 404


def test_posting_dir_in_config():
    private_key, public_key = generate_key_pair()
    server = get_test_client("examples/config/single_dir_single_policy.yml")

    response = server.post('/fetch/examples', json={'wrapping_key': format_public_key(public_key)})
    assert response.status_code == 200

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    absolute_target = os.path.join(project_root, "examples")
    assert zip_directory(absolute_target) == decrypt(response.json, private_key)


def test_request_without_json():
    server = get_test_client("examples/config/single_file_single_policy.yml")
    response = server.post('/fetch/readme.md', data="not json data", content_type="text/plain")
    assert response.status_code == 415
    assert b"Request body must be JSON" in response.data
