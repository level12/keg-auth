import arrow
from blazeutils.strings import randchars
import flask
from keg.db import db
from keg_elements.db.mixins import might_commit, might_flush
import shortuuid
import six
import sqlalchemy as sa
import sqlalchemy.orm as sa_orm
import sqlalchemy.sql as sa_sql
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_utils import ArrowType, EmailType, PasswordType, force_auto_coercion

from . import entity_registry

force_auto_coercion()


def _create_cryptcontext_kwargs(**column_kwargs):
    config = flask.current_app.config['PASSLIB_CRYPTCONTEXT_KWARGS']
    retval = {}
    retval.update(config)
    retval.update(column_kwargs)
    return retval


def _generate_session_key():
    return six.text_type(shortuuid.uuid())


class UserMixin(object):
    # These two attributes are needed by Flask-Login.
    is_anonymous = False
    is_authenticated = True

    # Assume the user will need to verify their email address before they become active.
    is_verified = sa.Column(sa.Boolean, nullable=False, default=False,
                            server_default=sa.text('false'))
    is_enabled = sa.Column(sa.Boolean, nullable=False, default=True, server_default=sa.true())
    is_superuser = sa.Column(sa.Boolean, nullable=False, default=False, server_default=sa.false())
    email = sa.Column(EmailType, nullable=False, unique=True)
    password = sa.Column(PasswordType(onload=_create_cryptcontext_kwargs))
    token = sa.Column(PasswordType(onload=_create_cryptcontext_kwargs))
    token_created_utc = sa.Column(ArrowType)

    # key used to identify the "id" for flask-login, which is expected to be a string. While we
    #   could return the user's db id cast to string, that would not give us a hook to reset
    #   sessions when permissions go stale
    session_key = sa.Column(sa.Unicode(36), nullable=False, unique=True,
                            default=_generate_session_key)

    def get_id(self):
        # Flask-Login requires that this return a string value for the session
        return str(self.session_key)

    def reset_session_key(self):
        self.session_key = _generate_session_key()

    @hybrid_property
    def is_active(self):
        return self.is_verified and self.is_enabled

    @is_active.expression
    def is_active(cls):
        return sa_sql.and_(cls.is_verified == sa.true(), cls.is_enabled == sa.true())

    @classmethod
    def testing_create(cls, **kwargs):
        kwargs['password'] = kwargs.get('password') or randchars()

        # Most tests will want an active user by default, which is the opposite of what we want in
        # production, so swap that logic.
        kwargs.setdefault('is_verified', True)

        user = super(UserMixin, cls).testing_create(**kwargs)
        user._plaintext_pass = kwargs['password']
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

    @might_commit
    def token_generate(self):
        token = shortuuid.uuid()
        self.token = token
        self.token_created_utc = arrow.get()

        # Store the plain text version on this instance for ease of use.  It will not get
        # pesisted to the db, so no security conern.
        self._token_plain = token

        return token

    @might_commit
    def change_password(self, token, new_password):
        """
            Change a password based on token authorization.
        """
        # May want to throw a custom exception here eventually.  Right now, assume calling code
        # will have verified the token before calling change_password() to provide a better UX
        # if the token is invalid.
        assert self.token_verify(token)

        self.token = None
        self.token_created_utc = None
        self.password = new_password
        self.is_verified = True

    def get_all_permissions(self):
        # Superusers are considered to have all permissions.
        if self.is_superuser:
            return set(entity_registry.registry.permission_cls.query)

        perm_cls = entity_registry.registry.permission_cls
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
        perm_cls = entity_registry.registry.permission_cls
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
        perm_cls = entity_registry.registry.permission_cls
        bundle_cls = entity_registry.registry.bundle_cls
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
        group_cls = entity_registry.registry.group_cls

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


class PermissionMixin(object):
    token = sa.Column(sa.Unicode, nullable=False, unique=True)
    description = sa.Column(sa.Unicode)

    @classmethod
    def get_by_token(cls, token):
        return cls.get_by(token=token)

    @classmethod
    def testing_create(cls, **kwargs):
        matching = None
        if 'token' in kwargs:
            matching = cls.get_by_token(kwargs['token'])
        return matching or super(PermissionMixin, cls).testing_create(**kwargs)


class BundleMixin(object):
    name = sa.Column(sa.Unicode, nullable=False, unique=True)

    @might_commit
    @might_flush
    @classmethod
    def edit(cls, oid=None, **kwargs):
        """obj = cls.query.get(oid)

        rights_keys = ('permissions', )
        original_rights = _rights_as_dict(obj, *rights_keys)
        original_users = {user.id for user in obj.users}
        original_groups = {group.id for group in obj.groups}"""

        obj = super(BundleMixin, cls).edit(oid=oid, _commit=False, **kwargs)

        """# if any users were added or removed, reset their session keys
        # if any groups were added or removed, reset their users' session keys
        # if this bundle's rights changed, reset all of the assigned users and group users
        user_cls = entity_registry.registry.user_cls
        reset_user_ids = original_users ^ {user.id for user in obj.users}
        if original_rights != _rights_as_dict(obj, *rights_keys):
            reset_user_ids |= {user.id for user in obj.users}

        for user_id in reset_user_ids:
            user_cls.query.get(user_id).session_key = _generate_session_key()"""

        return obj


class GroupMixin(object):
    name = sa.Column(sa.Unicode, nullable=False, unique=True)

    def get_all_permissions(self):
        perm_cls = entity_registry.registry.permission_cls
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
        perm_cls = entity_registry.registry.permission_cls
        bundle_cls = entity_registry.registry.bundle_cls

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


def initialize_mappings(namespace='keg_auth', registry=entity_registry.registry):
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


def initialize_events(registry=entity_registry.registry):
    # look for changes to rights throughout users, groups, and bundles before flush. Reset the
    #   session key when there is a change

    def _sa_attr_has_changes(target, attr):
        return sa_orm.attributes.get_history(target, attr).has_changes()

    @sa.event.listens_for(db.session, 'before_flush')
    def changed_users(session, *args):
        for target in session.new | session.dirty:
            if not isinstance(target, registry.user_cls):
                continue

            if (
                _sa_attr_has_changes(target, 'permissions') or
                _sa_attr_has_changes(target, 'groups') or
                _sa_attr_has_changes(target, 'bundles') or
                _sa_attr_has_changes(target, 'is_superuser') or
                _sa_attr_has_changes(target, 'is_enabled')
            ):
                target.reset_session_key()

    @sa.event.listens_for(db.session, 'before_flush')
    def changed_groups(session, *args):
        for target in session.new | session.dirty:
            if not isinstance(target, registry.group_cls):
                continue

            if (
                _sa_attr_has_changes(target, 'permissions') or
                _sa_attr_has_changes(target, 'bundles')
            ):
                for user in target.users:
                    user.reset_session_key()
            user_history = sa_orm.attributes.get_history(target, 'users')
            for user in user_history.added + user_history.deleted:
                user.reset_session_key()

        for target in session.deleted:
            if not isinstance(target, registry.group_cls):
                continue

            for user in target.users:
                user.reset_session_key()

    @sa.event.listens_for(db.session, 'before_flush')
    def changed_bundles(session, *args):
        for target in session.new | session.dirty:
            if not isinstance(target, registry.bundle_cls):
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
            if not isinstance(target, registry.bundle_cls):
                continue

            update_users = target.users
            for group in target.groups:
                update_users += group.users
            for user in update_users:
                user.reset_session_key()
