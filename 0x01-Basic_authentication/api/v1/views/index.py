#!/usr/bin/env python3
""" Module of Index views
"""
from flask import Flask, jsonify, abort, request
from api.v1.views import app_views
from flask_cors import (CORS, cross_origin)


@app_views.route('/unathourized', methods=['GET'], strict_slashes=False)
def unathorized()-> str:
    """GET /api/v1/unauthorized
    Return:
      - Error handler for 401
    """
    abort(401)


@app_views.route('/status', methods=['GET'], strict_slashes=False)
def status() -> str:
    """ GET /api/v1/status
    Return:
      - the status of the API
    """
    return jsonify({"status": "OK"})


@app_views.route('/stats/', strict_slashes=False)
def stats() -> str:
    """ GET /api/v1/stats
    Return:
      - the number of each objects
    """
    from models.user import User
    stats = {}
    stats['users'] = User.count()
    return jsonify(stats)