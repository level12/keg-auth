import itertools
import string
import random

from keg_auth.extensions import lazy_gettext as _


class PermissionCondition(object):
    """Basic permission condition that will return True/False upon user access check.

    One or more permissions or conditions must be provided to the constructor.
    """
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
    """Condition requiring all contained permissions/conditions to be satisfied.

    Rules governing the contained permission/conditions:
    - Not all conditions are guaranteed to be checked. Checking will exit on the first failure.
    - Callable conditions are expected to take a `user` argument.
    - Permission token conditions are run if the user has a `has_all_permissions` method
    (default case).
    """
    def check(self, user):
        for cond in self.conditions:
            if not self._check_condition(cond, user):
                return False
        return True


class AnyCondition(PermissionCondition):
    """Condition requiring only one of the contained permissions/conditions to be satisfied.

    Rules governing the contained permission/conditions:
    - Not all conditions are guaranteed to be checked. Checking will exit on the first success.
    - Callable conditions are expected to take a `user` argument.
    - Permission token conditions are run if the user has a `has_all_permissions` method
    (default case).
    """
    def check(self, user):
        for cond in self.conditions:
            if self._check_condition(cond, user):
                return True
        return False


def has_permissions(condition, user):
    """Check a user against a single condition/permission."""
    if condition is None:
        return True
    return PermissionCondition._check_condition(condition, user)


has_all = AllCondition
has_any = AnyCondition


def generate_password(length=12):
    if length < 10:
        raise Exception('length must be at least 10')

    charsets = (
        list(string.ascii_lowercase),
        list(string.ascii_uppercase),
        list(string.digits),
        list('!#$%&*+-/?@^_|~'),
    )
    [random.shuffle(charset) for charset in charsets]
    num_uppercase = int((length - 4) / 3)
    num_lowercase = length - 4 - num_uppercase
    lengths = (num_lowercase, num_uppercase, 2, 2)
    result = list(itertools.chain(*[charsets[i][:lengths[i]] for i in range(len(charsets))]))
    random.shuffle(result)
    return ''.join(result)
