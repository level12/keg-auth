
DEFAULT_PROFILE = 'DevProfile'


class DevProfile(object):
    SQLALCHEMY_DATABASE_URI = 'postgresql://rsyring@:5433/kegauth_ta'
    MAIL_DEFAULT_SENDER = 'randy.syring@level12.io'


class TestProfile(object):
    SQLALCHEMY_DATABASE_URI = 'postgresql://rsyring@:5433/test'
