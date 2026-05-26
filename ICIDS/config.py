import os
import secrets
from datetime import timedelta
from logging.config import dictConfig
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
UPLOAD_FOLDER = BASE_DIR / "static" / "uploads"


class BaseConfig:
    SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(
        minutes=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES_MINUTES", "30"))
    )
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(
        days=int(os.getenv("JWT_REFRESH_TOKEN_EXPIRES_DAYS", "7"))
    )
    JWT_TOKEN_LOCATION = ["headers"]
    JWT_HEADER_TYPE = "Bearer"
    JWT_COOKIE_SECURE = os.getenv("FLASK_ENV", "production") == "production"
    JWT_COOKIE_CSRF_PROTECT = True
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ["access", "refresh"]

    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'icids.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False

    SOCKETIO_MESSAGE_QUEUE = os.getenv("SOCKETIO_MESSAGE_QUEUE")
    SOCKETIO_ASYNC_MODE = os.getenv("SOCKETIO_ASYNC_MODE", "eventlet")
    SOCKETIO_CORS_ALLOWED_ORIGINS = [
        origin.strip() for origin in os.getenv("SOCKETIO_CORS_ALLOWED_ORIGINS", "*").split(",")
    ]

    UPLOAD_FOLDER = UPLOAD_FOLDER
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", 16 * 1024 * 1024))
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "csv", "json", "txt"}

    ENV = os.getenv("FLASK_ENV", "production")
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
    SESSION_PROTECTION = "strong"
    PREFERRED_URL_SCHEME = "https"
    CORS_HEADERS = ["Content-Type", "Authorization"]
    LOG_DIR = LOG_DIR
    LOG_FILE = LOG_DIR / "icids.log"

    @classmethod
    def init_app(cls, app):
        cls.LOG_DIR.mkdir(parents=True, exist_ok=True)
        cls.UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

        dictConfig(
            {
                "version": 1,
                "disable_existing_loggers": False,
                "formatters": {
                    "standard": {
                        "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                        "datefmt": "%Y-%m-%d %H:%M:%S",
                    }
                },
                "handlers": {
                    "console": {
                        "class": "logging.StreamHandler",
                        "formatter": "standard",
                        "level": "INFO",
                    },
                    "file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        "formatter": "standard",
                        "level": "INFO",
                        "filename": str(cls.LOG_FILE),
                        "maxBytes": 10 * 1024 * 1024,
                        "backupCount": 5,
                        "encoding": "utf-8",
                    },
                },
                "root": {"level": "INFO", "handlers": ["console", "file"]},
                "loggers": {
                    "sqlalchemy.engine": {"level": "WARNING"},
                    "werkzeug": {"level": "INFO"},
                },
            }
        )


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    ENV = "development"
    SQLALCHEMY_ECHO = True
    JWT_COOKIE_SECURE = False
    SESSION_COOKIE_SECURE = False
    PREFERRED_URL_SCHEME = "http"


class ProductionConfig(BaseConfig):
    DEBUG = False
    ENV = "production"
    SQLALCHEMY_ECHO = False
    JWT_COOKIE_SECURE = True
    SESSION_COOKIE_SECURE = True
    PREFERRED_URL_SCHEME = "https"


config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
}


def get_config():
    env = os.getenv("FLASK_ENV", "production").lower()
    return config_by_name.get(env, ProductionConfig)


def configure_app(app):
    app.config.from_object(get_config())
    get_config().init_app(app)
