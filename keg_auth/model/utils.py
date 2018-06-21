class PermissionCondition(object):
    def __init__(self, *conditions):
        assert len(conditions) >= 1, 'At least one permission or condition is required'
        self.conditions = conditions

    @staticmethod
    def _check_condition(condition, user):
        if isinstance(condition, PermissionCondition):
            return condition.check(user)
        if callable(condition):
            return condition(user)
        if not hasattr(user, 'has_all_permissions'):
            # probably an anonymous user in the session after logout
            return False
        return user.has_all_permissions(condition)

    def check(self, user):
        raise Exception('fill in the check method in the subclass')  # pragma: no cover


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
