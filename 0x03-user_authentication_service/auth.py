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

    return hashed_password


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
            raise ValueError("User {} already exists".format(email))
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

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """ finds a user by session_id """
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except Exception:
            return None
        return user

    def destroy_session(self, user_id: int) -> None:
        """ destroys the session by updating the user seeion id to None """
        if user_id is None:
            return
        try:
            user = self._db.find_user_by(id=user_id)
        except Exception:
            return
        self._db.update_user(user.id, session_id=None)
        return None

    def get_reset_password_token(self, email: str) -> str:
        """ returns a token to reset password """
        try:
            user = self._db.find_user_by(email=email)
        except Exception:
            raise ValueError
        if user:
            reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """ updates the password of a user """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            pwd = _hash_password(password)
            self._db.update_user(
                    user.id,
                    hashed_password=pwd,
                    reset_token=None,
            )
        except NoResultFound:
            raise ValueError
