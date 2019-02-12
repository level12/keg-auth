DEFAULT_PROFILE = 'DevProfile'


class DevProfile(object):
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:@localhost:5432/keg_auth_ta'
    MAIL_DEFAULT_SENDER = ''
    SERVER_NAME = 'localhost:5000'


class TestProfile(object):
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:@localhost:5432/__tests__'
