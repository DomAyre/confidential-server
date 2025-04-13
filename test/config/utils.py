import glob
import os
import yaml


def configs():
    for config_path in glob.glob("examples/config/*.yml"):
        if os.path.isfile(config_path):
            with open(config_path) as f:
                yield yaml.safe_load(f), config_path