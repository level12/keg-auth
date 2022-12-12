import base64
import binascii
import hashlib
import json
import time

import arrow
import flask
import keg_elements.db.utils as dbutils
import passlib.hash
import passlib.pwd
import shortuuid
import sqlalchemy as sa
import sqlalchemy.orm as sa_orm
import sqlalchemy.sql as sa_sql
from authlib import jose
from blazeutils import tolist
from blazeutils.strings import randchars
from keg.db import db
from keg_elements.db.mixins import might_commit, might_flush
from sqlalchemy.dialects import mssql
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_utils import (
    ArrowType,
    EmailType,
    PasswordType,
    force_auto_coercion,
)

from keg_auth.model.types import AttemptType

force_auto_coercion()


def registry():
    return flask.current_app.auth_manager.entity_registry


def _create_cryptcontext_kwargs(**column_kwargs):
    config = flask.current_app.config['PASSLIB_CRYPTCONTEXT_KWARGS']
    retval = {}
    retval.update(config)
    retval.update(column_kwargs)
    return retval


def _generate_session_key():
    return str(shortuuid.uuid())


class InvalidToken(Exception):
    pass


class KAPasswordType(PasswordType):
    def load_dialect_impl(self, dialect):
        if dialect.name == 'mssql':
            return mssql.VARCHAR(self.length)
        return super(KAPasswordType, self).load_dialect_impl(dialect)


class UserMixin(object):
    """Generic mixin for user entities."""
    # These two attributes are needed by Flask-Login.
    is_anonymous = False
    is_authenticated = True

    is_enabled = sa.Column(sa.Boolean, nullable=False, default=True)
    is_superuser = sa.Column(sa.Boolean, nullable=False, default=False)
    password = sa.Column(KAPasswordType(onload=_create_cryptcontext_kwargs))

    username = sa.Column(sa.Unicode(512), nullable=False, unique=True)

    # key used to identify the "id" for flask-login, which is expected to be a string. While we
    #   could return the user's db id cast to string, that would not give us a hook to reset
    #   sessions when permissions go stale
    session_key = sa.Column(sa.Unicode(36), nullable=False, unique=True,
                            default=_generate_session_key)

    # When a user logins we need to track their last login time
    # This is used in the salt to invalidate a password/verification token
    # when a user logs in.
    last_login_utc = sa.Column(ArrowType, nullable=True, default=None, server_default=None)

    # The datetime when a user will be disabled. User will be inactive if this is set
    # to a datetime in the past.
    disabled_utc = sa.Column(ArrowType, nullable=True, default=None, server_default=sa.null())

    # is_active defines the complexities of how to determine what users are active. For instance,
    #   if email is in scope, we need to have an additional flag to verify users, and that would
    #   get included in is_active logic.
    @hybrid_property
    def is_active(self):
        return not self.is_disabled_by_date and self.is_enabled

    @is_active.expression
    def is_active(cls):
        expr = sa_sql.and_(~cls.is_disabled_by_date, cls.is_enabled == sa.true())
        # need to wrap the expression in a case to work with MSSQL
        return sa_sql.case([(expr, sa.true())], else_=sa.false())

    @hybrid_property
    def is_disabled_by_date(self):
        return self.disabled_utc is not None and self.disabled_utc <= arrow.utcnow()

    @is_disabled_by_date.expression
    def is_disabled_by_date(cls):
        is_disabled_expr = sa.sql.and_(
            cls.disabled_utc.isnot(None),
            cls.disabled_utc <= arrow.utcnow(),
        )
        return sa_sql.case([(is_disabled_expr, sa.true())], else_=sa.false())

    def get_id(self):
        # Flask-Login requires that this return a string value for the session
        return str(self.session_key)

    def reset_session_key(self):
        self.session_key = _generate_session_key()

    @property
    def display_value(self):
        # shortcut to return the value of the user ident attribute
        return self.username

    @classmethod
    def fake(cls, **kwargs):
        kwargs['password'] = kwargs.get('password') or randchars()

        if 'permissions' in kwargs:
            perm_cls = registry().permission_cls

            # ensure all of the tokens exists
            flask.current_app.auth_manager.validate_permission_set(
                list(filter(
                    lambda perm: not isinstance(perm, perm_cls),
                    tolist(kwargs['permissions'])
                ))
            )

            kwargs['permissions'] = [
                perm_cls.fake(token=perm)
                if not isinstance(perm, perm_cls) else perm
                for perm in tolist(kwargs['permissions'])
            ]

        user = super(UserMixin, cls).fake(**kwargs)
        user._plaintext_pass = kwargs['password']
        return user

    def get_all_permissions(self):
        # Superusers are considered to have all permissions.
        if self.is_superuser:
            return set(registry().permission_cls.query)

        perm_cls = registry().permission_cls
        mapping = self._query_permission_mapping().alias('user_permission_mapping')
        q = db.session.query(
            perm_cls
        ).select_from(
            perm_cls
        ).join(
            mapping,
            mapping.c.perm_id == perm_cls.id
        ).filter(
            mapping.c.user_id == self.id
        )
        return set(q)

    def get_all_permission_tokens(self):
        # permission tokens for a given user should get loaded once per session. This method, called
        #   by has_all_permissions, is the main interface to grab them. So, set up a cache here, so
        #   the user instance stored by flask-login will hold the set to be used (rather than
        #   continuing to query the database on each permission check)
        # the other side to this is that permissions can become stale, because we are not querying
        #   the database every time. If an admin changes permissions while a user is actively
        #   logged in, we have to make sure the session is invalidated (see session_key field)
        if not hasattr(self, '_permission_cache'):
            self._permission_cache = {p.token for p in self.get_all_permissions()}
        return self._permission_cache

    def has_all_permissions(self, *tokens):
        return set(tokens).issubset(self.get_all_permission_tokens())

    def has_any_permission(self, *tokens):
        return bool(set(tokens).intersection(self.get_all_permission_tokens()))

    @classmethod
    def _query_permission_mapping(cls):
        return sa.union(
            cls._query_direct_permissions(),
            cls._query_bundle_permissions(),
            cls._query_group_permissions()
        )

    @classmethod
    def _query_direct_permissions(cls):
        perm_cls = registry().permission_cls
        return db.session.query(
            cls.id.label('user_id'),
            perm_cls.id.label('perm_id'),
        ).select_from(
            cls
        ).join(
            cls.permissions
        )

    @classmethod
    def _query_bundle_permissions(cls):
        perm_cls = registry().permission_cls
        bundle_cls = registry().bundle_cls
        return db.session.query(
            cls.id.label('user_id'),
            perm_cls.id.label('perm_id'),
        ).select_from(
            cls
        ).join(
            cls.bundles
        ).join(
            bundle_cls.permissions
        )

    @classmethod
    def _query_group_permissions(cls):
        group_cls = registry().group_cls

        group_mapping = group_cls._query_permission_mapping().alias('group_permissions_mapping')
        return db.session.query(
            cls.id.label('user_id'),
            group_mapping.c.perm_id.label('perm_id')
        ).select_from(
            cls
        ).join(
            cls.groups
        ).join(
            group_mapping,
            group_mapping.c.group_id == group_cls.id
        )

    def get_token_salt(self):
        """
        Create salt data for password reset token signing. The return value will be hashed
        together with the signing key. This ensures that changes to any of the fields included
        in the salt invalidates any tokens produced with the old values
        Values included:

            * user login identifier -> if username/email change it will invalidate
                                       the user token
            * is_active -> Anytime a user verifies will invalidate a token

            * current password hash or empty string if no password has been set
              -> If the password is updated we want to invalidate the token

            * last login time -> Any time a user logs in it will invalidate any
                                 verification and reset password emails

        :return: JSON string of list containing the values listed above
        """
        return json.dumps([
            self.display_value,
            str(self.is_active),
            self.password.hash.decode() if self.password is not None else '',
            self.last_login_utc.to('UTC').isoformat() if self.last_login_utc else None
        ])

    def get_token_signature(self, digest_method=hashlib.sha512):
        base_key = (
            self.get_token_salt()
            + 'signer'
            + flask.current_app.config.get('SECRET_KEY')
        )
        return digest_method(base_key.encode()).digest()

    def get_token_payload(self, payload, expires_in):
        now = int(time.time())
        exp = now + expires_in
        payload['iat'] = payload.get('iat', now)
        payload['exp'] = payload.get('exp', exp)
        return payload

    def token_verify(self, token, _use_legacy=False, _block_legacy=False):
        """
        Verify a password reset token. The token is validated for:
            * user identity
            * tampering
            * expiration
            * password was not already reset since token was generated
            * user has not signed in since token was generated

        :param token: string representation of token to verify
        :return: bool indicating token validity
        """
        if not token:
            return False
        if isinstance(token, str):
            token = token.encode()

        """
        We used to use itsdangerous to generate/verify these JWT tokens. In version 2.1,
        itsdangerous removed those wrappers, so we switched to authlib. A few key
        differences need to be handled (temporarily) to support tokens generated with
        itsdangerous:
        - digest_method was supposed to be sha512, but due to a bug in ID it fell back to SHA1
        - iat/exp claims were in the header generated by ID, not the payload

        If we need to fall back to legacy mode due to sha512 not matching signature, we can
        assume that the token was generated by ID (or by a test mimicing it).
        """
        digest_method = hashlib.sha512 if not _use_legacy else hashlib.sha1

        try:
            payload = jose.jwt.decode(token, self.get_token_signature(digest_method))
            if _use_legacy:
                payload['iat'] = payload.header.get('iat')
                payload['exp'] = payload.header.get('exp')
            payload.validate()
        except (
            jose.errors.DecodeError,
            jose.errors.ExpiredTokenError
        ):
            return False
        except jose.errors.BadSignatureError:
            if not _use_legacy and not _block_legacy:
                # bad sig could mean it's an itsdangerous token, try legacy mode
                return self.token_verify(token, _use_legacy=True)
            return False

        # authlib treats iat/exp claims as optional. We need to make sure they were in
        # the payload, and fail if not
        if len({'iat', 'exp'} & set(payload.keys())) != 2:
            return False

        return payload['user_id'] == self.id

    def token_generate(self):
        """
        Create a new token for this user. The returned value is an expiring JWT
        signed with the application's crypto key. Externally this token should be treated as opaque.
        The value returned by this function must not be persisted.
        :return: a string representation of the generated token
        """
        payload = self.get_token_payload(
            {'user_id': self.id},
            flask.current_app.config['KEGAUTH_TOKEN_EXPIRE_MINS'] * 60
        )
        header = {'alg': 'HS512'}
        token = jose.jwt.encode(header, payload, self.get_token_signature()).decode()

        # Store the plain text version on this instance for ease of use.  It will not get
        # pesisted to the db, so no security conern.
        self._token_plain = token

        return token


class UserTokenMixin(object):
    """Mixin for users who will be authenticated by tokens."""
    token = sa.Column(KAPasswordType(onload=_create_cryptcontext_kwargs))

    @classmethod
    def generate_raw_auth_token(cls, length=32, entropy=None, charset='ascii_50'):
        """Return a raw authentication token

        NOTE(nZac): You should not store this directly in the database. When using this mixin,
        simply setting this value to ``self.token = generate_raw_auth_token`` is enough (though,
        there is a helper method for that ``reset_auth_token``).
        """
        return passlib.pwd.genword(length=length, entropy=entropy, charset=charset)

    @classmethod
    def get_user_for_api_token(cls, api_token):
        if api_token is None:
            return

        if isinstance(api_token, bytes):
            api_token = api_token.decode()

        if len(api_token.split('.')) != 2:
            return

        raw_email, raw_token = api_token.split('.')
        try:
            real_email = base64.urlsafe_b64decode(raw_email.encode()).decode()
        except (binascii.Error, TypeError):
            return

        user = cls.query.filter_by(email=real_email).one_or_none()
        if user is None or not user.token.context.verify(raw_token, user.token.hash):
            return
        else:
            return user

    def reset_auth_token(self, **kwargs):
        """Reset the authentication token for this user

        Takes the same parameter as `:cls:generate_auth_token`
        """
        self.token = raw = self.generate_raw_auth_token(**kwargs)
        return raw

    def verify_token(self, token):
        if not token or not self.token:
            return False

        return self.token.context.verify(token, self.token.hash)

    def generate_api_token(self, token=None):
        raw_token = token or self.reset_auth_token()

        url_safe_email = base64.urlsafe_b64encode(self.email.encode()).decode()

        raw_api_token = '{email}.{token}'.format(
            email=url_safe_email,
            token=raw_token,
        )

        return raw_api_token


class UserEmailMixin(object):
    """Mixin for users who will be authenticated by email/password."""
    # Assume the user will need to verify their email address before they become active.
    is_verified = sa.Column(sa.Boolean, nullable=False, default=False)
    email = sa.Column(EmailType, nullable=False, unique=True)

    @hybrid_property
    def username(self):
        return self.email

    @username.expression
    def username(cls):
        return cls.email

    @hybrid_property
    def is_active(self):
        return not self.is_disabled_by_date and self.is_verified and self.is_enabled

    @is_active.expression
    def is_active(cls):
        expr = sa_sql.and_(
            ~cls.is_disabled_by_date,
            cls.is_verified == sa.true(),
            cls.is_enabled == sa.true(),
        )
        # need to wrap the expression in a case to work with MSSQL
        return sa_sql.case([(expr, sa.true())], else_=sa.false())

    @classmethod
    def fake(cls, **kwargs):
        # Most tests will want an active user by default, which is the opposite of what we want in
        # production, so swap that logic.
        kwargs.setdefault('is_verified', True)

        user = super(UserEmailMixin, cls).fake(**kwargs)
        return user

    @might_commit
    def change_password(self, token, new_password):
        """
            Change a password based on token authorization.
        """
        if not self.token_verify(token):
            raise InvalidToken

        self.password = new_password
        self.is_verified = True


class PermissionMixin(object):
    """Generic mixin for permissions."""
    token = sa.Column(sa.Unicode(1024), nullable=False, unique=True)
    description = sa.Column(sa.Unicode)

    @classmethod
    def get_by_token(cls, token):
        return cls.get_by(token=token)

    @classmethod
    def fake(cls, **kwargs):
        matching = None
        if 'token' in kwargs:
            matching = cls.get_by_token(kwargs['token'])
        return matching or super(PermissionMixin, cls).fake(**kwargs)


class BundleMixin(object):
    """Generic mixin for permission bundles."""
    name = sa.Column(sa.Unicode(1024), nullable=False, unique=True)

    @might_commit
    @might_flush
    @classmethod
    def edit(cls, oid=None, **kwargs):
        obj = super(BundleMixin, cls).edit(oid, _commit=False, **kwargs)
        return obj


class GroupMixin(object):
    """Generic mixin for user groups."""
    name = sa.Column(sa.Unicode(1024), nullable=False, unique=True)

    def get_all_permissions(self):
        perm_cls = registry().permission_cls
        mapping = self._query_permission_mapping().alias('group_permissions_mapping')
        q = db.session.query(
            perm_cls
        ).select_from(
            perm_cls
        ).join(
            mapping,
            mapping.c.perm_id == perm_cls.id
        ).filter(
            mapping.c.group_id == self.id
        )
        return set(q)

    @classmethod
    def _query_permission_mapping(cls):
        perm_cls = registry().permission_cls
        bundle_cls = registry().bundle_cls

        direct = db.session.query(
            cls.id.label('group_id'),
            perm_cls.id.label('perm_id')
        ).join(
            cls.permissions
        )

        via_bundle = db.session.query(
            cls.id.label('group_id'),
            perm_cls.id.label('perm_id')
        ).join(
            cls.bundles
        ).join(
            bundle_cls.permissions
        )
        return sa.union(direct, via_bundle)


class AttemptMixin(object):
    """Generic mixin for logging user login attempts."""
    # Form input data, e.g. username
    user_input = sa.Column(sa.Unicode(512), nullable=False)

    datetime_utc = sa.Column(ArrowType, nullable=False, default=arrow.utcnow,
                             server_default=dbutils.utcnow())
    attempt_type = sa.Column(AttemptType.db_type())
    is_during_lockout = sa.Column(sa.Boolean, nullable=False, default=False)
    success = sa.Column(sa.Boolean, nullable=False, default=True)
    source_ip = sa.Column(sa.Unicode(50), nullable=True)

    @classmethod
    def purge_attempts(cls, username=None, older_than=None, attempt_type=None):
        """Delete attempt records optionally filtered by username, age, or type."""
        query = cls.query
        if username:
            query = query.filter_by(user_input=username)

        if older_than:
            query = query.filter(cls.datetime_utc < arrow.utcnow().shift(days=-older_than))

        if attempt_type:
            query = query.filter_by(attempt_type=attempt_type)

        count = query.delete()
        db.session.commit()
        return count


def get_username(user):
    """Based on the registered user entity, find the column representing the login ID."""
    user_cls = registry().get_entity_cls('user')
    return getattr(user, get_username_key(user_cls))


def get_username_key(user_cls):
    obj = user_cls.username
    if not isinstance(obj, (sa.Column, sa_orm.attributes.InstrumentedAttribute)):
        obj = obj.descriptor.expr(user_cls)
    return obj.key


def _make_mapping_table(table_name, **foreign_cols):
    columns = (
        sa.Column(key, fc.type, sa.ForeignKey(fc, ondelete='CASCADE'), nullable=False,
                  primary_key=True)
        for key, fc in foreign_cols.items()
    )
    return db.Table(
        table_name,
        *columns
    )


def user_permission_mapping(user_cls, permission_cls, table_name='user_permissions',
                            user_id_attr='id', permission_id_attr='id',
                            user_rel_property='permissions'):
    table = _make_mapping_table(
        table_name,
        user_id=getattr(user_cls, user_id_attr),
        permission_id=getattr(permission_cls, permission_id_attr)
    )
    if user_rel_property:
        setattr(
            user_cls, user_rel_property,
            sa.orm.relationship(permission_cls, secondary=table)
        )

    return table


def bundle_permission_mapping(bundle_cls, permission_cls, table_name='bundle_permissions',
                              bundle_id_attr='id', permission_id_attr='id',
                              rel_property='permissions'):
    table = _make_mapping_table(
        table_name,
        bundle_id=getattr(bundle_cls, bundle_id_attr),
        permission_id=getattr(permission_cls, permission_id_attr)
    )

    if rel_property:
        setattr(
            bundle_cls, rel_property,
            sa.orm.relationship(permission_cls, secondary=table)
        )
    return table


def user_bundle_mapping(user_cls, bundle_cls, table_name='user_bundles',
                        user_id_attr='id', bundle_id_attr='id',
                        rel_property='bundles'):
    table = _make_mapping_table(
        table_name,
        user_id=getattr(user_cls, user_id_attr),
        bundle_id=getattr(bundle_cls, bundle_id_attr),
    )
    if rel_property:
        setattr(
            user_cls, rel_property,
            sa.orm.relationship(bundle_cls, secondary=table, backref='users')
        )
    return table


def user_group_mapping(user_cls, group_cls, table_name='user_groups',
                       user_id_attr='id', group_id_attr='id',
                       rel_property='groups'):
    table = _make_mapping_table(
        table_name,
        user_id=getattr(user_cls, user_id_attr),
        group_id=getattr(group_cls, group_id_attr),
    )
    if rel_property:
        setattr(
            user_cls, rel_property,
            sa.orm.relationship(group_cls, secondary=table, backref='users')
        )
    return table


def group_permission_mapping(group_cls, permission_cls, table_name='group_permissions',
                             group_id_attr='id', permission_id_attr='id',
                             rel_property='permissions'):
    table = _make_mapping_table(
        table_name,
        group_id=getattr(group_cls, group_id_attr),
        permission_id=getattr(permission_cls, permission_id_attr),
    )
    if rel_property:
        setattr(
            group_cls, rel_property,
            sa.orm.relationship(permission_cls, secondary=table)
        )
    return table


def group_bundle_mapping(group_cls, bundle_cls, table_name='group_bundles',
                         group_id_attr='id', bundle_id_attr='id',
                         rel_property='bundles'):
    table = _make_mapping_table(
        table_name,
        group_id=getattr(group_cls, group_id_attr),
        bundle_id=getattr(bundle_cls, bundle_id_attr),
    )
    if rel_property:
        setattr(
            group_cls, rel_property,
            sa.orm.relationship(bundle_cls, secondary=table, backref='groups')
        )
    return table


def initialize_mappings(namespace='keg_auth', registry=None):
    def _make_table_name(default_name):
        return '{}_{}'.format(namespace, default_name) if namespace else default_name

    mappings = {
        'user_permissions': (user_permission_mapping, 'user', 'permission'),
        'bundle_permissions': (bundle_permission_mapping, 'bundle', 'permission'),
        'user_bundles': (user_bundle_mapping, 'user', 'bundle'),
        'user_groups': (user_group_mapping, 'user', 'group'),
        'group_permissions': (group_permission_mapping, 'group', 'permission'),
        'group_bundles': (group_bundle_mapping, 'group', 'bundle')
    }
    tables = {}
    for base_name, mapping_data in mappings.items():
        table_func, type1, type2 = mapping_data
        table1 = registry.get_entity_cls(type1)
        table2 = registry.get_entity_cls(type2)

        tables[base_name] = table_func(table1, table2, table_name=_make_table_name(base_name))

    return tables


def initialize_events(registry=None):
    # look for changes to rights throughout users, groups, and bundles before flush. Reset the
    #   session key when there is a change
    def _isinstance(target, cls):
        # use a more simplistic method of determining type for performance
        return type(target) is cls

    def _sa_attr_has_changes(target, attr):
        try:
            return sa_orm.attributes.get_history(target, attr).has_changes()
        except KeyError as exc:
            if attr not in str(exc):
                raise
        return False

    @sa.event.listens_for(db.session, 'before_flush')
    def changed_users(session, *args):
        for target in session.new | session.dirty:
            if not _isinstance(target, registry.user_cls):
                continue

            if (
                _sa_attr_has_changes(target, 'permissions')
                or _sa_attr_has_changes(target, 'groups')
                or _sa_attr_has_changes(target, 'bundles')
                or _sa_attr_has_changes(target, 'is_superuser')
                or _sa_attr_has_changes(target, 'is_enabled')
            ):
                target.reset_session_key()

    @sa.event.listens_for(db.session, 'before_flush')
    def re_enabling_users(session, *args):
        for target in session.dirty:
            if not _isinstance(target, registry.user_cls):
                continue

            if (
                target.is_disabled_by_date
                and target.is_enabled
                and _sa_attr_has_changes(target, 'is_enabled')
                and not _sa_attr_has_changes(target, 'disabled_utc')
            ):
                target.disabled_utc = None

    @sa.event.listens_for(db.session, 'before_flush')
    def changed_groups(session, *args):
        for target in session.new | session.dirty:
            if not _isinstance(target, registry.group_cls):
                continue

            if (
                _sa_attr_has_changes(target, 'permissions')
                or _sa_attr_has_changes(target, 'bundles')
            ):
                for user in target.users:
                    user.reset_session_key()
            user_history = sa_orm.attributes.get_history(target, 'users')
            for user in user_history.added + user_history.deleted:
                user.reset_session_key()

        for target in session.deleted:
            if not _isinstance(target, registry.group_cls):
                continue

            for user in target.users:
                user.reset_session_key()

    @sa.event.listens_for(db.session, 'before_flush')
    def changed_bundles(session, *args):
        for target in session.new | session.dirty:
            if not _isinstance(target, registry.bundle_cls):
                continue

            if _sa_attr_has_changes(target, 'permissions'):
                for user in target.users:
                    user.reset_session_key()
                for group in target.groups:
                    for user in group.users:
                        user.reset_session_key()
            user_history = sa_orm.attributes.get_history(target, 'users')
            update_users = user_history.added + user_history.deleted

            group_history = sa_orm.attributes.get_history(target, 'groups')
            for group in group_history.added + group_history.deleted:
                update_users += tuple(group.users)

            for user in update_users:
                user.reset_session_key()

        for target in session.deleted:
            if not _isinstance(target, registry.bundle_cls):
                continue

            update_users = target.users
            for group in target.groups:
                update_users += group.users
            for user in update_users:
                user.reset_session_key()
