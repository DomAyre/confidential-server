from base64 import b64decode
from typing import cast
from flask import Flask, request
from config.parser import ServerConfig
from encryption_wrapper.src.lib.b64_to_public_key import b64_to_public_key
from server.args import parse_args
from endpoints.fetch import fetch as _fetch

def create_app(args):

    app = Flask(__name__)
    config = cast(ServerConfig, args.config)

    @app.route('/fetch/<path:target>', methods=['POST'])
    def fetch(target: str):

        # Parse attestation
        attestation_b64 = request.json.get('attestation')
        if attestation_b64 is None:
            return "Missing attestation.", 400
        try:
            attestation = b64decode(attestation_b64).decode()
        except (binascii.Error, UnicodeDecodeError):
            return "Invalid base64 attestation", 403

        return _fetch(
            config,
            target,
            attestation,
            b64_to_public_key(request.json.get('wrapping_key')),
        )

    return app

if __name__ == '__main__':
    create_app(parse_args()).run(debug=True)
