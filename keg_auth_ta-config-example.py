DEFAULT_PROFILE = 'DevProfile'


class DevProfile(object):
    MAIL_DEFAULT_SENDER = ''
    SERVER_NAME = 'localhost:5000'
    # SQLALCHEMY_DATABASE_URI = 'postgresql://postgres@localhost/postgres'


class TestProfile(object):
    # SQLALCHEMY_DATABASE_URI = 'postgresql://postgres@localhost/kegauth_tests'
    pass
