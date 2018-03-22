import abc


class PermissionCondition(abc.ABC):
    def __init__(self, *conditions):
        assert len(conditions) >= 1, 'At least one permission or condition is required'
        self.conditions = conditions

    def _check_condition(self, user, condition):
        if isinstance(condition, PermissionCondition):
            return condition.check(user)
        if callable(condition):
            return condition(user)
        return user.has_all_permissions(condition)

    @abc.abstractmethod
    def check(self, user):
        pass


class AllCondition(PermissionCondition):
    def check(self, user):
        for cond in self.conditions:
            if not self._check_condition(user, cond):
                return False
        return True


class AnyCondition(PermissionCondition):
    def check(self, user):
        for cond in self.conditions:
            if self._check_condition(user, cond):
                return True
        return False


def has_permissions(condition, user):
    if isinstance(condition, PermissionCondition):
        return condition.check(user)
    return user.has_all_permissions(condition)


has_all = AllCondition
has_any = AnyCondition
