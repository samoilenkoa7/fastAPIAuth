from datetime import datetime, timedelta

from pydantic import ValidationError
from starlette import status
from fastapi.security import OAuth2PasswordBearer

from wrokshop import tables
from wrokshop.database import get_session
from wrokshop.models.auth import User, UserCreate, Token
from wrokshop.settings import settings
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException
from passlib.hash import bcrypt

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/auth/sign-in')


def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    return AuthServices.validate_token(token)


class AuthServices:
    @classmethod
    def validate_passwords(cls, plain_password: str, hashed_password: str) -> bool:
        return bcrypt.verify(plain_password, hashed_password)

    @classmethod
    def hash_password(cls, password: str) -> str:
        return bcrypt.hash(password)

    @classmethod
    def validate_token(cls, token: str) -> User:
        exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Provided credentials are not valid'
        )
        try:
            playload = jwt.decode(
                token,
                settings.jwt_secret,
                algorithms=[settings.jwt_algorithm]
            )
        except JWTError:
            raise exception

        user_data = playload.get('user')
        try:
            user = User.parse_obj(user_data)
        except ValidationError:
            raise exception from None

        return user

    @classmethod
    def create_token(cls, user: tables.User) -> Token:
        user_data = User.from_orm(user)
        now = datetime.utcnow()

        playload = {
            'iat': now,
            'nbf': now,
            'exp': now + timedelta(seconds=settings.jwt_expiration),
            'sub': str(user_data.id),
            'user': user_data.dict(),
        }

        token = jwt.encode(
            playload,
            settings.jwt_secret,
            algorithm=settings.jwt_algorithm
        )
        return Token(access_token=token)

    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    def register_new_user(self, user_data: UserCreate) -> Token:
        user = tables.User(
            username=user_data.username,
            email=user_data.email,
            hashed_password=self.hash_password(user_data.password)
        )
        self.session.add(user)
        self.session.commit()

        return self.create_token(user)

    def login_user(self, username: str, password: str) -> Token:
        exception = HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='Password or/and username are not valid'
        )
        user = self.session.query(tables.User).filter_by(username=username).first()
        if not user:
            raise exception
        if not self.validate_passwords(password, user.hashed_password):
            raise exception

        return self.create_token(user)
