#!/usr/bin/env python3
"""Defines _hash_password method, takes in a pswd string args&returns bytes"""
import bcrypt
from typing import Union


def _hash_password(self, password: str) -> bytes:
    """returns salted hash of the input password, hashed with bcrypt.hashpw"""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    return hashed_password
