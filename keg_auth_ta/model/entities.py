import logging

from keg.db import db
from keg_elements.db.mixins import DefaultColsMixin, MethodsMixin
import keg_auth
import sqlalchemy as sa

from keg_auth_ta.extensions import auth_entity_registry

log = logging.getLogger(__name__)


class EntityMixin(DefaultColsMixin, MethodsMixin):
    pass


class UserEmailMixin(keg_auth.UserEmailMixin, keg_auth.UserMixin):
    pass


@auth_entity_registry.register_user
class User(UserEmailMixin, EntityMixin, db.Model):
    __tablename__ = 'users'

    name = sa.Column(sa.Unicode)


class UserNoEmail(keg_auth.UserMixin, EntityMixin, db.Model):
    __tablename__ = 'users_no_email'

    # this model will not be assigned the relationships the form expects to be present
    permissions = []
    bundles = []
    groups = []


class UserWithToken(keg_auth.UserTokenMixin, UserEmailMixin, EntityMixin, db.Model):
    __tablename__ = 'users_with_token'


@auth_entity_registry.register_attempt
class Attempt(keg_auth.AttemptMixin, EntityMixin, db.Model):
    __tablename__ = 'attempts'


@auth_entity_registry.register_permission
class Permission(keg_auth.PermissionMixin, EntityMixin, db.Model):
    __tablename__ = 'permissions'

    def __repr__(self):
        return '<Permission id={} token={}>'.format(self.id, self.token)


@auth_entity_registry.register_bundle
class Bundle(keg_auth.BundleMixin, EntityMixin, db.Model):
    __tablename__ = 'bundles'


@auth_entity_registry.register_group
class Group(keg_auth.GroupMixin, EntityMixin, db.Model):
    __tablename__ = 'groups'
