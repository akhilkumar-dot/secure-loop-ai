# Sample 14: Insecure Deserialization via Python pickle (Vulnerable)
# Source: OWASP Benchmark / CWE-502
# License: Apache-2.0

import pickle
import base64
from flask import Flask, request

app = Flask(__name__)

@app.route("/load_session", methods=["POST"])
def load_session():
    data = base64.b64decode(request.form["session_data"])
    # Vulnerability: pickle.loads executes arbitrary code defined in __reduce__
    session = pickle.loads(data)
    return f"Loaded session for user: {session.get('user')}"

