import os
from config.parser import ServerConfig
from flask import jsonify

from encryption_wrapper.src.encrypt import encrypt
from encryption_wrapper.src.lib.b64_to_public_key import b64_to_public_key
from encryption_wrapper.src.lib.zip_directory import zip_directory

def fetch(req, target: str, args: ServerConfig):

    if not req.is_json:
        return jsonify({"error": "Request body must be JSON"}), 415

    wrapping_key = b64_to_public_key(req.json.get('wrapping_key'))

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    absolute_target = os.path.join(project_root, target)

    # Ensure target is an actual file or directory and defined in the server
    # configuration. The application shouldn't distinguish between files which
    # don't exist and files not included in the configuration.
    if not os.path.exists(absolute_target) or target not in (target.path for target in args.config.serve):
        return f"Target '{target}' does not exist.", 404

    # If it's a file, just send it, if it's a directory, zip it first
    if os.path.isfile(absolute_target):
        with open(absolute_target, 'rb') as file:
            return jsonify(encrypt(file.read(), wrapping_key)), 200
    else:
        return jsonify(encrypt(zip_directory(absolute_target), wrapping_key)), 200
