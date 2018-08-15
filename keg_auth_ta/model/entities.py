import logging

from keg.db import db
from keg_elements.db.mixins import DefaultColsMixin, MethodsMixin
import keg_auth

from keg_auth_ta.extensions import auth_entity_registry

log = logging.getLogger(__name__)


class EntityMixin(DefaultColsMixin, MethodsMixin):
    pass


@auth_entity_registry.register_user
class User(db.Model, keg_auth.UserEmailMixin, keg_auth.UserMixin, EntityMixin):
    __tablename__ = 'users'


class UserNoEmail(db.Model, keg_auth.UserMixin, EntityMixin):
    __tablename__ = 'users_no_email'


@auth_entity_registry.register_permission
class Permission(db.Model, keg_auth.PermissionMixin, EntityMixin):
    __tablename__ = 'permissions'

    def __repr__(self):
        return '<Permission id={} token={}>'.format(self.id, self.token)


@auth_entity_registry.register_bundle
class Bundle(db.Model, keg_auth.BundleMixin, EntityMixin):
    __tablename__ = 'bundles'


@auth_entity_registry.register_group
class Group(db.Model, keg_auth.GroupMixin, EntityMixin):
    __tablename__ = 'groups'
