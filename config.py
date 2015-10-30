import os
from datetime import timedelta
basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    # Custom app config.
    APP_TITLE = 'WebApp'
    APP_MAIL_NAME = '%s Admin' % APP_TITLE
    APP_MAIL_ADDRESS = 'webapp@example.com'
    APP_MAIL_SENDER = '%s <%s>' % (APP_MAIL_NAME, APP_MAIL_ADDRESS)
    APP_MAIL_SUBJECT_PREFIX = '[%s]' % APP_TITLE
    APP_ADMIN = os.environ.get('APP_ADMIN')
    # Allow new users to register.
    APP_ALLOW_NEW_USERS = True
    # A value of 0 means unlimited.
    APP_MAX_USERS = 2

    # Flask config.
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard to guess string'

    # Flask-Login config.
    SESSION_PROTECTION = None
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_DURATION = timedelta(days=365)

    # Flask-Mail config.
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')

    # Flask-SQLAlchemy config.
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    # Flask config.
    DEBUG = True

    # Flask-SQLAlchemy config.
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'data-dev.sqlite')


class TestingConfig(Config):
    # Flask config.
    TESTING = True

    # Flask-SQLAlchemy config.
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'data-test.sqlite')


class ProductionConfig(Config):
    # Flask config.
    # Uncomment the following line if you're running HTTPS.
    # SESSION_COOKIE_SECURE = True

    # Flask-Login config.
    # Uncomment the following line if you're running HTTPS.
    # REMEMBER_COOKIE_SECURE = True

    # Flask-SQLAlchemy config.
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'data.sqlite')


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,

    'default': DevelopmentConfig
}
