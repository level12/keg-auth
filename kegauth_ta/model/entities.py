import logging

from keg.db import db
from keg_elements.db.mixins import DefaultColsMixin, MethodsMixin
from kegauth.model import UserMixin, PasswordMixin

log = logging.getLogger(__name__)


class EntityMixin(DefaultColsMixin, MethodsMixin):
    pass


class User(db.Model, PasswordMixin, UserMixin, EntityMixin):
    __tablename__ = 'users'


