#!/usr/bin/env python3
"""This module checks if a given API route (path requires authentication)"""
from flask import request
from typing import List, TypeVar


class Auth():
    """This class gives Public method definition of class"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """It returns False if path and excluded paths"""

        if path is None or excluded_paths is None or not len(excluded_paths):
            return True

        if not path.endswith('/'):
            path += '/'

        # if path[-1] != '/':
        #    path += '/'

        for i in excluded_paths:
            if i.endswith('*'):
                if path.startswith(i[:1]):
                    return False

        if path in excluded_paths:
            return False
        else:
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
