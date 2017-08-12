
DEFAULT_PROFILE = 'DevProfile'


class DevProfile:
    SQLALCHEMY_DATABASE_URI = 'postgresql://rsyring@:5433/kegauth_ta'


class TestProfile:
    SQLALCHEMY_DATABASE_URI = 'postgresql://rsyring@:5433/test'
