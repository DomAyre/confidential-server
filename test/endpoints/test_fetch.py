from argparse import Namespace
from config.parser import parse_config_file
from server.run import create_app
import zipfile
import io

def get_test_client(config_path):
    return create_app(args=Namespace(
        config=parse_config_file(config_path),
    )).test_client()


def test_requesting_file_in_config():
    server = get_test_client("examples/config/single_file_single_policy.yml")
    response = server.post('/fetch/readme.md', json={'wrapping_key': None})
    assert response.status_code == 200


def test_posting_file_which_doesnt_exist():
    server = get_test_client("examples/config/single_file_single_policy.yml")
    response = server.post('/fetch/doesnt_exist.md', json={'wrapping_key': None})
    assert response.status_code == 404


def test_posting_file_not_in_config():
    server = get_test_client("examples/config/single_file_single_policy.yml")
    response = server.post('/fetch/license', json={'wrapping_key': None})
    assert response.status_code == 404


def test_posting_dir_in_config():
    server = get_test_client("examples/config/single_dir_single_policy.yml")

    response = server.post('/fetch/examples', json={'wrapping_key': None})
    assert response.status_code == 200

    zip_file = zipfile.ZipFile(io.BytesIO(response.data))
    assert len(zip_file.namelist()) > 0


def test_request_without_json():
    server = get_test_client("examples/config/single_file_single_policy.yml")
    response = server.post('/fetch/readme.md', data="not json data", content_type="text/plain")
    assert response.status_code == 415
    assert b"Request body must be JSON" in response.data
