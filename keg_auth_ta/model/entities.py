import logging

from keg.db import db
from keg_elements.db.mixins import DefaultColsMixin, MethodsMixin
from keg_auth.model.entity_registry import registry
from keg_auth import UserMixin, PermissionMixin, BundleMixin, GroupMixin

log = logging.getLogger(__name__)


class EntityMixin(DefaultColsMixin, MethodsMixin):
    pass


@registry.register_user
class User(db.Model, UserMixin, EntityMixin):
    __tablename__ = 'users'


@registry.register_permission
class Permission(db.Model, PermissionMixin, EntityMixin):
    __tablename__ = 'permissions'


@registry.register_bundle
class Bundle(db.Model, BundleMixin, EntityMixin):
    __tablename__ = 'bundles'


@registry.register_group
class Group(db.Model, GroupMixin, EntityMixin):
    __tablename__ = 'groups'
