from flask import Flask, jsonify
from provider import Provider

app = Flask(__name__)

@app.route("/combined_hosts")
def index():
    return jsonify(provider.get_combined_info())

if __name__ == '__main__':
    provider = Provider()
    app.run(debug=True,host='0.0.0.0',port=5000)
