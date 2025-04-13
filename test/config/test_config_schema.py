import pytest
import yaml
from jsonschema import validate
from utils import configs


@pytest.fixture
def schema():
    with open("src/config/schema.yml") as f:
        return yaml.safe_load(f)


@pytest.mark.parametrize("config", configs(), ids=lambda c: c[1])
def test_example_config_matches_schema(config, schema):
    validate(instance=config[0], schema=schema)
