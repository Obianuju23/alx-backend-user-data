#!/usr/bin/env python3
"""set up a basic Flask app"""
from flask import Flask, jsonify, request, abort, make_response
from flask import redirect
from auth import Auth

Auth = Auth()
app = Flask(__name__)


@app.route('/')
def welcome() -> str:
    """ returns a jsonify payload """
    return jsonify({"message": "Bienvenue"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
