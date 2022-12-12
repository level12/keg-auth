from blazeutils.strings import randchars
from keg import config


class DefaultProfile(object):
    SECRET_KEY = randchars()

    KEG_BASE_TEMPLATE = 'base-page.html'
    KEGAUTH_TEMPLATE_TITLE_VAR = 'title'

    # These three just get rid of warnings on the console.
    KEG_KEYRING_ENABLE = False
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres@localhost/postgres'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SITE_NAME = 'Keg Auth Demo'
    SITE_ABBR = 'KA Demo'

    AUTO_EXPAND_MENU = True


class TestProfile(object):
    # Make tests faster
    PASSLIB_CRYPTCONTEXT_KWARGS = dict(schemes=['plaintext'])

    MAIL_DEFAULT_SENDER = 'sender@example.com'

    # These settings reflect what is needed in CI & when using docker compose.
    # Use keg_auth_ta-config.py to override if needed.
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres@localhost/kegauth_tests'


class TestProfileUserArgs(config.TestProfile, TestProfile):
    KEGAUTH_CLI_USER_ARGS = ['name', 'email']
