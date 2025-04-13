from flask import Flask
from server.args import parse_args
from endpoints.fetch import fetch as _fetch

def create_app(args):

    app = Flask(__name__)

    @app.route('/fetch/<path:target>', methods=['GET'])
    def fetch(target):
        return _fetch(target, args)

    return app

if __name__ == '__main__':
    create_app(parse_args()).run(debug=True)
