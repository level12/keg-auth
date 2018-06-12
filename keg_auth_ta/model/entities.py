import logging

from keg.db import db
from keg_elements.db.mixins import DefaultColsMixin, MethodsMixin
from keg_auth import UserMixin, PermissionMixin, BundleMixin, GroupMixin, auth_entity_registry

log = logging.getLogger(__name__)


class EntityMixin(DefaultColsMixin, MethodsMixin):
    pass


@auth_entity_registry.register_user
class User(db.Model, UserMixin, EntityMixin):
    __tablename__ = 'users'


@auth_entity_registry.register_permission
class Permission(db.Model, PermissionMixin, EntityMixin):
    __tablename__ = 'permissions'

    def __repr__(self):
        return '<Permission id={} token={}>'.format(self.id, self.token)


@auth_entity_registry.register_bundle
class Bundle(db.Model, BundleMixin, EntityMixin):
    __tablename__ = 'bundles'


@auth_entity_registry.register_group
class Group(db.Model, GroupMixin, EntityMixin):
    __tablename__ = 'groups'
