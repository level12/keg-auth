import arrow
from blazeutils.strings import randchars
import flask
import shortuuid
import sqlalchemy as sa
import sqlalchemy.sql as sa_sql
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_utils import ArrowType, EmailType, PasswordType, force_auto_coercion

force_auto_coercion()


def _create_cryptcontext_kwargs(**column_kwargs):
    config = flask.current_app.config['PASSLIB_CRYPTCONTEXT_KWARGS']
    retval = {}
    retval.update(config)
    retval.update(column_kwargs)
    return retval


class UserMixin:
    # These two fields are needed by Flask-Login.
    is_anonymous = False
    is_authenticated = True
    # Assume the user will need to verify their email address before they become active.
    is_verified = sa.Column(sa.Boolean, nullable=False, default=False,
                            server_default=sa.text('false'))
    is_enabled = sa.Column(sa.Boolean, nullable=False, default=True, server_default=sa.text('true'))
    email = sa.Column(EmailType, nullable=False, unique=True)
    password = sa.Column(PasswordType(onload=_create_cryptcontext_kwargs), nullable=False)
    token = sa.Column(PasswordType(onload=_create_cryptcontext_kwargs))
    token_created_utc = sa.Column(ArrowType)

    def get_id(self):
        # Flask-Login requires that this return a unicode value.  We are assuming at this point
        # that the entity this is mixed into will have it's PK as .id.
        return str(self.id)

    @hybrid_property
    def is_active(self):
        return self.is_verified and self.is_enabled

    @is_active.expression
    def is_active(self):
        return sa_sql.and_(self.is_verified == sa.true(), self.is_enabled == sa.true())

    @classmethod
    def testing_create(cls, **kwargs):
        kwargs['password'] = kwargs.get('password') or randchars()

        # Most tests will want an active user by default, which is the opposite of what we want in
        # production, so swap that logic.
        kwargs.setdefault('is_verified', True)

        user = super(UserMixin, cls).testing_create(**kwargs)
        return user

    def token_verify(self, token):
        # If a token isn't set, it's can't be verified.
        if token is None or self.token is None or self.token_created_utc is None:
            return False

        # The token is invalid if it has expired.
        expire_mins = flask.current_app.config['KEGAUTH_TOKEN_EXPIRE_MINS']
        expire_at = self.token_created_utc.shift(minutes=expire_mins)
        if arrow.get() >= expire_at:
            return False

        return self.token == token

    def token_generate(self):
        token = shortuuid.uuid()
        self.token = token
        self.token_created_utc = arrow.get()

        # Store the plain text version on this instance for ease of use.  It will not get
        # pesisted to the db, so no security conern.
        self._token_plain = token

        return token

    def change_password(self, token, new_password):
        # May want to throw a custom exception here eventually.  Right now, assume calling code
        # will have verified the token before calling change_password()
        assert self.token_verify(token)

        self.token = None
        self.password = new_password

