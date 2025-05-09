import os
import subprocess
import docker
import pytest


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

@pytest.fixture()
def server():
    process = subprocess.Popen([
        "python", "src/server/run.py",
        "--config", "examples/config/single_file_single_dir_single_policy.yml"
    ])
    yield
    process.terminate()
    process.wait()


def build_image(client, dockerfile: str, **kwargs):
    return client.images.build(
        path=PROJECT_ROOT,
        dockerfile=dockerfile,
        tag="virtual-attestation-client",
        **kwargs,
    )[0]


def test_virtual_attestation_client_build_and_run(server):
    client = docker.from_env()
    container_logs = client.containers.run(
        image=build_image(
            client,
            f"{PROJECT_ROOT}/examples/clients/virtual_attestation.Dockerfile",
        ),
        network="host"
    )
    with open(f"{PROJECT_ROOT}/readme.md", "rb") as file:
        assert container_logs.strip() == file.read().strip()
