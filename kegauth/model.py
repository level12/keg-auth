from blazeutils.strings import randchars
import flask
import sqlalchemy as sa
import sqlalchemy.sql as sa_sql
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_utils import EmailType, PasswordType


def _create_cryptcontext_kwargs(**column_kwargs):
    config = flask.current_app.config['PASSLIB_CRYPTCONTEXT_KWARGS']
    retval = {}
    retval.update(config)
    retval.update(column_kwargs)
    return retval


class PasswordMixin:
    password = sa.Column(PasswordType(onload=_create_cryptcontext_kwargs), nullable=False)


class UserMixin:
    # These two fields are needed by Flask-Login.
    is_anonymous = False
    is_authenticated = True
    # Assume the user will need to verify their email address before they become active.
    is_verified = sa.Column(sa.Boolean, nullable=False, default=False,
                            server_default=sa.text('false'))
    is_enabled = sa.Column(sa.Boolean, nullable=False, default=True, server_default=sa.text('true'))
    email = sa.Column(EmailType, nullable=False, unique=True)

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
