import argparse
from config.parser import parse_config_file


def parse_args():
    parser = argparse.ArgumentParser(description='Run the Flask application.')
    parser.add_argument(
        '--config',
        help='Path to the config file',
        type=parse_config_file,
        required=True
    )
    return parser.parse_args()
