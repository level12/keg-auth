import inspect

from keg_auth.extensions import lazy_gettext as _


class RegistryError(Exception):
    pass


class EntityRegistry(object):
    """Registry cache that identifies entities for particular usage/function in KegAuth.

    KegAuth does not provide its own entities for the database model. Instead, mixins are
    given so that an application can customize as needed. To support this model and still
    know what entity to use, we register it in an EntityRegistry.

    Entities may be registered in one of two ways:
    - Mark an entity with a registration decorator::

        @registry.register_user
        class User(UserMixin, db.EntityBase):
            pass

    - Pass the entity into the EntityRegistry constructor::

        registry = EntityRegistry(user=User, permission=Permission, ...)

    Registered entities may be subsequently referenced via the properties, e.g.

        registry.user_cls
    """
    def __init__(self, user=None, permission=None, bundle=None, group=None, attempt=None):
        self._user_cls = user
        self._permission_cls = permission
        self._bundle_cls = bundle
        self._group_cls = group
        self._attempt_cls = attempt

    def _type_to_attr(self, type):
        return '_{}_cls'.format(type)

    def register_entity(self, type, cls):
        attr = self._type_to_attr(type)
        try:
            if getattr(self, attr) is not None:
                raise RegistryError(_('Entity class already registered for {}').format(type))
        except AttributeError:
            raise RegistryError(_('Attempting to register unknown type {}').format(type))
        if not inspect.isclass(cls):
            raise RegistryError(_('Entity must be a class'))

        setattr(self, attr, cls)
        return cls

    def register_user(self, cls):
        """Mark given class as the entity for User."""
        return self.register_entity('user', cls)

    def register_permission(self, cls):
        """Mark given class as the entity for Permission."""
        return self.register_entity('permission', cls)

    def register_bundle(self, cls):
        """Mark given class as the entity for Bundle."""
        return self.register_entity('bundle', cls)

    def register_group(self, cls):
        """Mark given class as the entity for Group."""
        return self.register_entity('group', cls)

    def register_attempt(self, cls):
        """Mark given class as the entity for Attempt."""
        return self.register_entity('attempt', cls)

    def get_entity_cls(self, type):
        attr = self._type_to_attr(type)
        try:
            cls = getattr(self, attr)
        except AttributeError:
            raise RegistryError(_('Attempting to register unknown type {}').format(type))

        if cls is None:
            raise RegistryError(_('No entity registered for {}').format(type))
        return cls

    @property
    def user_cls(self):
        """Return the entity registered for User."""
        return self.get_entity_cls('user')

    @property
    def permission_cls(self):
        """Return the entity registered for Permission."""
        return self.get_entity_cls('permission')

    @property
    def bundle_cls(self):
        """Return the entity registered for Bundle."""
        return self.get_entity_cls('bundle')

    @property
    def group_cls(self):
        """Return the entity registered for Group."""
        return self.get_entity_cls('group')

    @property
    def attempt_cls(self):
        """Return the entity registered for Attempt."""
        return self.get_entity_cls('attempt')

    def is_registered(self, type):
        """Helper for determining if functionality is unlocked via a registered entity."""
        attr = self._type_to_attr(type)
        return getattr(self, attr, None) is not None


# Example
# @registry.register_user
# class User(db.EntityBase, UserMixin):
#     pass
