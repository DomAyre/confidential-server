import os
import subprocess
import docker
import pytest


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

@pytest.fixture()
def server():
    subprocess.Popen([
        "python", "src/server/run.py",
        "--config", "examples/config/single_file_single_dir_single_policy.yml"
    ])
    yield
    subprocess.Popen([
        "pkill", "-f", "python src/server/run.py"
    ])


def build_image(dockerfile: str, **kwargs):
    client = docker.from_env()
    return client, client.images.build(
        path=PROJECT_ROOT,
        dockerfile=dockerfile,
        tag="logger-client",
        **kwargs,
    )[0]


def test_logger_client_build(server):
    client, logger_image = build_image(f"{PROJECT_ROOT}/examples/clients/logger.Dockerfile")
    container_logs = client.containers.run(
        image=logger_image,
        network="host"
    )
    with open(f"{PROJECT_ROOT}/readme.md", "r") as file:
        assert container_logs.decode("utf-8") == file.read()
