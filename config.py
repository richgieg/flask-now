import os
from datetime import timedelta
basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    ###########################################################################
    # [ Application ]
    ###########################################################################
    APP_TITLE = 'WebApp'
    APP_MAIL_NAME = '%s Support' % APP_TITLE
    APP_MAIL_ADDRESS = 'support@webapp.com'
    APP_MAIL_SENDER = '%s <%s>' % (APP_MAIL_NAME, APP_MAIL_ADDRESS)
    APP_MAIL_SUBJECT_PREFIX = '[%s]' % APP_TITLE
    # Email address for the primary site administrator user account.
    APP_ADMIN = os.environ.get('APP_ADMIN')
    # Allow new users to register.
    APP_ALLOW_NEW_USERS = True
    # A value of 0 means unlimited.
    APP_MAX_USERS = 2
    # Toggles the logging of user events.
    APP_EVENT_LOGGING = True

    ###########################################################################
    # [ Flask ]
    ###########################################################################
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard to guess string'

    ###########################################################################
    # [ Flask-Login ]
    ###########################################################################
    # Ensures that the "remember me" cookie isn't accessible by
    # client-sides scripts.
    REMEMBER_COOKIE_HTTPONLY = True
    # Time-to-live for the "remember me" cookie.
    REMEMBER_COOKIE_DURATION = timedelta(days=365)
    # Must be disabled for the application's security layer to
    # function properly.
    SESSION_PROTECTION = None

    ###########################################################################
    # [ Flask-Mail ]
    ###########################################################################
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')

    ###########################################################################
    # [ Flask-SQLAlchemy ]
    ###########################################################################
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    ###########################################################################
    # [ Flask ]
    ###########################################################################
    DEBUG = True

    ###########################################################################
    # [ Flask-SQLAlchemy ]
    ###########################################################################
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'data-dev.sqlite')


class TestingConfig(Config):
    ###########################################################################
    # [ Flask ]
    ###########################################################################
    TESTING = True

    ###########################################################################
    # [ Flask-SQLAlchemy ]
    ###########################################################################
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'data-test.sqlite')


class ProductionConfig(Config):
    ###########################################################################
    # [ Flask ]
    ###########################################################################
    # Uncomment the following line if you're running HTTPS throughout
    # your entire application.
    # SESSION_COOKIE_SECURE = True

    ###########################################################################
    # [ Flask-Login ]
    ###########################################################################
    # Uncomment the following line if you're running HTTPS throughout
    # your entire application.
    # REMEMBER_COOKIE_SECURE = True

    ###########################################################################
    # [ Flask-SQLAlchemy ]
    ###########################################################################
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'data.sqlite')


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,

    'default': DevelopmentConfig
}
