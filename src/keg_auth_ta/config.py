import os

from blazeutils.strings import randchars
from keg import config


POSTGRES_DRIVER = os.environ.get('POSTGRES_DRIVER', '+psycopg')
POSTGRES_HOST = os.environ.get('KEG_AUTH_DB_IP', '127.0.0.1')
POSTGRES_PORT = os.environ.get('KEG_AUTH_DB_PORT', '5432')


class DefaultProfile:
    SECRET_KEY = randchars(64)

    KEG_BASE_TEMPLATE = 'base-page.html'
    KEGAUTH_TEMPLATE_TITLE_VAR = 'title'

    # These three just get rid of warnings on the console.
    KEG_KEYRING_ENABLE = False
    SQLALCHEMY_DATABASE_URI = (
        f'postgresql{POSTGRES_DRIVER}://postgres@{POSTGRES_HOST}:{POSTGRES_PORT}/postgres'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SITE_NAME = 'Keg Auth Demo'
    SITE_ABBR = 'KA Demo'

    AUTO_EXPAND_MENU = True


class TestProfile:
    # Make tests faster
    KEGAUTH_PASSWORD_CONTEXT_KWARGS = dict(schemes=['plaintext'])

    MAIL_DEFAULT_SENDER = 'sender@example.com'

    # These settings reflect what is needed in CI & when using docker compose.
    # Use keg_auth_ta-config.py to override if needed.
    SQLALCHEMY_DATABASE_URI = (
        f'postgresql{POSTGRES_DRIVER}://postgres@{POSTGRES_HOST}:{POSTGRES_PORT}/kegauth_tests'
    )


class TestProfileUserArgs(config.TestProfile, TestProfile):
    KEGAUTH_CLI_USER_ARGS = ['name', 'email']
