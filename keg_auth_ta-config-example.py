
DEFAULT_PROFILE = 'DevProfile'


class DevProfile(object):
    SQLALCHEMY_DATABASE_URI = 'postgresql://rsyring@:5433/keg_auth_ta'
    MAIL_DEFAULT_SENDER = 'randy.syring@level12.io'
    SERVER_NAME = 'localhost:5000'


class TestProfile(object):
    SQLALCHEMY_DATABASE_URI = 'postgresql://rsyring@:5433/test'
