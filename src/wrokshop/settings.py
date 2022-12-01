from pydantic import BaseSettings


class Settings(BaseSettings):
    database_url: str = 'sqlite:///./database.sqlite3'
    server_host: str = '127.0.0.1'
    server_port: int = 8000

    jwt_secret: str
    jwt_algorithm: str = 'HS256'
    jwt_expiration: int = 3600  # seconds


settings = Settings(
    _env_file='.env',
    _env_file_encoding='utf-8'
)
