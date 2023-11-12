#!/usr/bin/env python3
"""This module checks if a given API route (path requires authentication)"""
from flask import request
from typing import List, TypeVar
from os import getenv


class Auth():
    """This class gives Public method definition of class"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """It returns False if path and excluded paths"""

        if path is None or not excluded_paths:
            return True
        for i in excluded_paths:
            if i.endswith('*') and path.startswith(i[:-1]):
                return False
            elif i in {path, path + '/'}:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """Funtion that manages authorization header"""

        if request is None:
            return None

        if not request.headers.get("Authorization"):
            return None

        return request.headers.get("Authorization")

    def current_user(self, request=None) -> TypeVar('User'):
        """ current user """

        return None

    def session_cookie(self, request=None):
        """ returns a cookie value from a request """
        if request is None:
            return None
        _my_session_id = request.cookies.get(getenv('SESSION_NAME'))
        return _my_session_id
