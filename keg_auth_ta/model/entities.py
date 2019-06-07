import logging

from keg.db import db
from keg_elements.db.mixins import DefaultColsMixin, MethodsMixin
import keg_auth

from keg_auth_ta.extensions import auth_entity_registry

log = logging.getLogger(__name__)


class EntityMixin(DefaultColsMixin, MethodsMixin):
    pass


@auth_entity_registry.register_user
class User(keg_auth.UserEmailMixin, keg_auth.UserMixin, EntityMixin, db.Model):
    __tablename__ = 'users'


class UserNoEmail(keg_auth.UserMixin, EntityMixin, db.Model):
    __tablename__ = 'users_no_email'


class UserWithToken(keg_auth.UserEmailMixin, keg_auth.UserTokenMixin,  EntityMixin, db.Model):
    __tablename__ = 'users_with_token'


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
