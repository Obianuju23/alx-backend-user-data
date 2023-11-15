#!/usr/bin/env python3
"""Defines _hash_password method, takes in a pswd string args&returns bytes"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4
from typing import Union


def _hash_password(password: str) -> bytes:
    """returns salted hash of the input password, hashed with bcrypt.hashpw"""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    return


def _generate_uuid() -> str:
    """generate uuid"""
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Takes in email and password arguments"""
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))

    def valid_login(self, email: str, password: str) -> bool:
        """ validates credentials """
        try:
            user = self._db.find_user_by(email=email)
            if user:
                pwd = bcrypt.checkpw(password.encode(), user.hashed_password)
                if pwd is True:
                    return True
                return False
        except Exception:
            return False

    def create_session(self, email: str) -> str:
        """ creates a session for a user with the email """
        try:
            user = self._db.find_user_by(email=email)
        except Exception:
            return None
        if user:
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        return None
