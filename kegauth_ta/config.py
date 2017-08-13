from blazeutils.strings import randchars


class DefaultProfile:
    SECRET_KEY = randchars()

    # These three just get rid of warnings on the console.
    KEG_KEYRING_ENABLE = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SITE_NAME = 'Keg Auth Demo'
    SITE_ABBR = 'KA Demo'


class TestProfile:
    # Make tests faster
    PASSLIB_CRYPTCONTEXT_KWARGS = dict(schemes=['plaintext'])

    MAIL_DEFAULT_SENDER = 'sender@example.com'
