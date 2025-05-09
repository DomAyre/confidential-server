import os
import base64
from config.parser import ServerConfig
from flask import jsonify
from cryptography.hazmat.primitives.asymmetric import rsa

from encryption_wrapper.src.encrypt import encrypt
from encryption_wrapper.src.lib.zip_directory import zip_directory
from attestation import verify_attestation_ccf

def fetch(config: ServerConfig, target: str, attestation: str, wrapping_key: rsa.RSAPublicKey):

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    absolute_target = os.path.join(project_root, target)

    try:
        if not verify_attestation_ccf(
            ccf_attestation=attestation,
            report_data="example-report-data",
            security_policy_b64=list(config.security_policies.items())[0][1],
        ):
            return "Invalid attestation.", 403
    except Exception:
        return "Invalid attestation encoding.", 400

    # Ensure target is an actual file or directory and defined in the server
    # configuration. The application shouldn't distinguish between files which
    # don't exist and files not included in the configuration.
    if not os.path.exists(absolute_target) or target not in (target.path for target in config.serve):
        return f"Target '{target}' does not exist.", 404

    # If it's a file, just send it, if it's a directory, zip it first
    if os.path.isfile(absolute_target):
        with open(absolute_target, 'rb') as file:
            return jsonify(encrypt(file.read(), wrapping_key)), 200
    else:
        return jsonify(encrypt(zip_directory(absolute_target), wrapping_key)), 200
