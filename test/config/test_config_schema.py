import os
import pytest
import yaml
import glob
from jsonschema import validate


@pytest.fixture
def schema():
    with open("src/config/schema.yml") as f:
        return yaml.safe_load(f)


def configs():
    for config_path in glob.glob(f"{"examples/config"}/*.yml"):
        if os.path.isfile(config_path):
            with open(config_path) as f:
                yield yaml.safe_load(f), config_path


@pytest.mark.parametrize("config", configs(), ids=lambda c: c[1])
def test_example_config_matches_schema(config, schema):
    validate(instance=config[0], schema=schema)
