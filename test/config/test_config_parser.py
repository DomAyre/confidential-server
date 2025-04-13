import pytest
from utils import configs
import yaml
from src.config.parse import parse_config_file
import tempfile


@pytest.mark.parametrize("config", configs(), ids=lambda c: c[1])
def test_example_config_parses_without_error(config):
    parse_config_file(config[1])


def test_config_with_mismatched_policy_name():

    with tempfile.NamedTemporaryFile("w", prefix="config_") as f:
        yaml.dump({
            "serve": [
                {
                    "path": "readme.md",
                    "policies": "not_a_policy"
                }
            ],
            "security_policies": {
                "allow_all": "abc123"
            }
        }, f)
        f.flush()

        with pytest.raises(ValueError, match="Policy 'not_a_policy' not found in security policies."):
            parse_config_file(f.name)


def test_config_with_non_existing_file():

    with tempfile.NamedTemporaryFile("w", prefix="config_") as f:
        yaml.dump({
            "serve": [
                {
                    "path": "not_a_file.md",
                    "policies": "allow_all"
                }
            ],
            "security_policies": {
                "allow_all": "abc123"
            }
        }, f)
        f.flush()

        with pytest.raises(FileNotFoundError, match="Path 'not_a_file.md' does not exist."):
            parse_config_file(f.name)