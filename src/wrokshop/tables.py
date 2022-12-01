from sqlalchemy.ext.declarative import declarative_base

import sqlalchemy as sa

Base = declarative_base()


class User(Base):
    __tablename__ = 'users'

    id = sa.Column(sa.Integer, primary_key=True)
    username = sa.Column(sa.Text, unique=True)
    email = sa.Column(sa.Text, unique=True)
    hashed_password = sa.Column(sa.Text)
