
DEFAULT_PROFILE = 'DevProfile'


class DevProfile:
    SQLALCHEMY_DATABASE_URI = 'postgresql://rsyring@:5433/kegauth_ta'
    MAIL_DEFAULT_SENDER = 'randy.syring@level12.io'


class TestProfile:
    SQLALCHEMY_DATABASE_URI = 'postgresql://rsyring@:5433/test'
