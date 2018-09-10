from keg_auth.extensions import lazy_gettext as _


class PermissionCondition(object):
    def __init__(self, *conditions):
        if len(conditions) < 1:
            raise ValueError(_('At least one permission or condition is required'))
        self.conditions = conditions

    @staticmethod
    def _check_condition(condition, user):
        if isinstance(condition, PermissionCondition):
            return condition.check(user)
        if callable(condition):
            return condition(user)
        if hasattr(user, 'has_all_permissions'):
            return user.has_all_permissions(condition)

        # probably an anonymous user in the session after logout
        return False

    def check(self, user):
        raise NotImplementedError  # pragma: no cover


class AllCondition(PermissionCondition):
    def check(self, user):
        for cond in self.conditions:
            if not self._check_condition(cond, user):
                return False
        return True


class AnyCondition(PermissionCondition):
    def check(self, user):
        for cond in self.conditions:
            if self._check_condition(cond, user):
                return True
        return False


def has_permissions(condition, user):
    if condition is None:
        return True
    return PermissionCondition._check_condition(condition, user)


has_all = AllCondition
has_any = AnyCondition
