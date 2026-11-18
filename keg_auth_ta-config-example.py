DEFAULT_PROFILE = 'DevProfile'


class DevProfile:
    MAIL_DEFAULT_SENDER = ''
    SERVER_NAME = 'localhost:5000'
    # SQLALCHEMY_DATABASE_URI = 'postgresql://postgres@localhost/postgres'


class TestProfile:
    # SQLALCHEMY_DATABASE_URI = 'postgresql://postgres@localhost/kegauth_tests'
    pass
