from flask import Flask
from args import parse_args
from endpoints.fetch import fetch as _fetch

app = Flask(__name__)
args = parse_args()

@app.route('/fetch/<path:target>', methods=['GET'])
def fetch(target):
    return _fetch(target, args)

if __name__ == '__main__':
    app.run(debug=True)