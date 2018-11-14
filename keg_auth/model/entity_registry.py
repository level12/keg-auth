import inspect

from keg_auth.extensions import lazy_gettext as _


class RegistryError(Exception):
    pass


class EntityRegistry(object):
    def __init__(self, user=None, permission=None, bundle=None, group=None):
        self._user_cls = user
        self._permission_cls = permission
        self._bundle_cls = bundle
        self._group_cls = group

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
        return self.register_entity('user', cls)

    def register_permission(self, cls):
        return self.register_entity('permission', cls)

    def register_bundle(self, cls):
        return self.register_entity('bundle', cls)

    def register_group(self, cls):
        return self.register_entity('group', cls)

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
        return self.get_entity_cls('user')

    @property
    def permission_cls(self):
        return self.get_entity_cls('permission')

    @property
    def bundle_cls(self):
        return self.get_entity_cls('bundle')

    @property
    def group_cls(self):
        return self.get_entity_cls('group')

    def is_registered(self, type):
        attr = self._type_to_attr(type)
        return getattr(self, attr, None) is not None


# Example
# @registry.register_user
# class User(db.EntityBase, UserMixin):
#     pass
