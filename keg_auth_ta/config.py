from blazeutils.strings import randchars
from keg import config


class DefaultProfile(object):
    SECRET_KEY = randchars()

    # These three just get rid of warnings on the console.
    KEG_KEYRING_ENABLE = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SITE_NAME = 'Keg Auth Demo'
    SITE_ABBR = 'KA Demo'

    AUTO_EXPAND_MENU = True


class TestProfile(object):
    # Make tests faster
    PASSLIB_CRYPTCONTEXT_KWARGS = dict(schemes=['plaintext'])

    MAIL_DEFAULT_SENDER = 'sender@example.com'

    # These settings reflect what is needed in CI.  For local development, use
    # keg_auth_ta-config.py to override.
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:password@localhost/postgres'


class TestProfileUserArgs(config.TestProfile, TestProfile):
    KEGAUTH_CLI_USER_ARGS = ['name', 'email']
