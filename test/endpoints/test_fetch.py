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
    response = server.get('/fetch/readme.md')
    assert response.status_code == 200


def test_requesting_file_which_doesnt_exist():
    server = get_test_client("examples/config/single_file_single_policy.yml")
    response = server.get('/fetch/doesnt_exist.md')
    assert response.status_code == 404


def test_requesting_file_not_in_config():
    server = get_test_client("examples/config/single_file_single_policy.yml")
    response = server.get('/fetch/license')
    assert response.status_code == 404


def test_requesting_dir_in_config():
    server = get_test_client("examples/config/single_dir_single_policy.yml")

    response = server.get('/fetch/examples')
    assert response.status_code == 200

    zip_file = zipfile.ZipFile(io.BytesIO(response.data))
    assert len(zip_file.namelist()) > 0
