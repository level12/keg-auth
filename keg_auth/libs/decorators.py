import inspect

from blazeutils import tolist
import flask
import flask_login
from keg.web import validate_arguments, ArgumentValidationError, ViewArgumentError

from keg_auth.libs.authenticators import Authenticator
from keg_auth.model import utils as model_utils


class RequiresUser(object):
    def __init__(self, authenticators=[], on_authentication_failure=None,
                 on_authorization_failure=None):
        self.authenticators = tolist(authenticators)

        # defaults for these handlers are provided, but may be overridden here
        self._on_authentication_failure = on_authentication_failure
        self._on_authorization_failure = on_authorization_failure

    def __call__(self, class_or_function):
        # decorator may be applied to a class or a function, but the effect is different
        if inspect.isclass(class_or_function):
            if issubclass(class_or_function, flask.Blueprint):
                return self.decorate_blueprint(class_or_function)
            return self.decorate_class(class_or_function)
        return self.decorate_function(class_or_function)

    def store_auth_info(self, obj):
        obj.__keg_auth_requires_user__ = True

    def decorate_blueprint(self, bp):
        # when decorating a blueprint, we simply need to attach a before_request method
        old_init = getattr(bp, '__init__')

        def new_init(*args, **kwargs):
            old_init(*args, **kwargs)

            this = args[0]
            this.before_request(self.check_auth)

        bp.__init__ = new_init
        self.store_auth_info(bp)
        return bp

    def decorate_class(self, cls):
        # when decorating a view class, all of the class's route methods will submit to the given
        #   auth. The view may already have check_auth defined, though, so make sure we still call
        #   it.
        old_check_auth = getattr(cls, 'check_auth', lambda: None)

        def new_check_auth(*args, **kwargs):
            self.check_auth()

            # the original check_auth method on the view may take any number of args/kwargs. Use
            #   logic similar to keg.web's _call_with_expected_args, except that method does not
            #   fit this case for bound methods
            try:
                # validate_arguments is made for a function, not a class method
                # so we need to "trick" it by sending self here, but then
                # removing it before the bound method is called below
                pass_args, pass_kwargs = validate_arguments(old_check_auth, args, kwargs.copy())
            except ArgumentValidationError as e:
                msg = 'Argument mismatch occured: method=%s, missing=%s, ' \
                      'extra_keys=%s, extra_pos=%s.' \
                      '  Arguments available: %s' % (old_check_auth, e.missing, e.extra,
                                                     e.extra_positional, kwargs)  # pragma: no cover
                raise ViewArgumentError(msg)  # pragma: no cover

            return old_check_auth(*pass_args, **pass_kwargs)

        cls.check_auth = new_check_auth

        # store auth info on the class itself
        self.store_auth_info(cls)
        return cls

    def decorate_function(self, func):
        # when decorating a function, we wrap it to check the auth first, then call the original
        #   function. Set the name on the wrapper for it to be available when assigning a route
        def wrapper(*args, **kwargs):
            self.check_auth()
            return func(*args, **kwargs)
        wrapper.__name__ = getattr(func, '__name__', 'wrapper')
        wrapper.__keg_auth_original_function__ = func

        # store auth info on the wrapper, as it is now the view method that will get stored for
        #   the app's routes
        self.store_auth_info(wrapper)
        return wrapper

    def on_authentication_failure(self):
        if self._on_authentication_failure:
            self._on_authentication_failure()

        should_redirect = False

        for authenticator in (
            self.authenticators or [flask.current_app.auth_manager.primary_authenticator]
        ):
            auth_instance = authenticator if isinstance(authenticator, Authenticator) else \
                flask.current_app.auth_manager.get_authenticator(authenticator)
            should_redirect = should_redirect or auth_instance.authentication_failure_redirect

        if should_redirect:
            redirect_resp = flask.current_app.login_manager.unauthorized()
            flask.abort(redirect_resp)
        else:
            flask.abort(401)

    def on_authorization_failure(self):
        if self._on_authorization_failure:
            self._on_authorization_failure()
        flask.abort(403)

    def check_auth(self):
        for authenticator in (
            self.authenticators or [flask.current_app.auth_manager.primary_authenticator]
        ):
            auth_instance = authenticator if isinstance(authenticator, Authenticator) else \
                flask.current_app.auth_manager.get_authenticator(authenticator)
            user = auth_instance.get_authenticated_user()
            if user:
                break
        if not user or not user.is_authenticated:
            self.on_authentication_failure()


class RequiresPermissions(RequiresUser):
    """ Require a user to be conditionally authorized before proceeding to decorated target. May be
        used as a class decorator or method decorator.

        Usage: @requires_permissions(condition)

        Note: if using along with a route decorator (e.g. Blueprint.route), requires_permissions
            should be the closest decorator to the method

        Examples:
        - @requires_permissions(('token1', 'token2'))
        - @requires_permissions(has_any('token1', 'token2'))
        - @requires_permissions(has_all('token1', 'token2'))
        - @requires_permissions(has_all(has_any('token1', 'token2'), 'token3'))
        - @requires_permissions(custom_authorization_callable that takes user arg)
    """
    def __init__(self, condition, authenticators=[], on_authentication_failure=None,
                 on_authorization_failure=None):
        super(RequiresPermissions, self).__init__(
            authenticators=authenticators,
            on_authentication_failure=on_authentication_failure,
            on_authorization_failure=on_authorization_failure,
        )
        self.condition = condition

    def store_auth_info(self, obj):
        super(RequiresPermissions, self).store_auth_info(obj)
        obj.__keg_auth_requires_permissions__ = self.condition

    def check_auth(self):
        super(RequiresPermissions, self).check_auth()

        user = flask_login.current_user
        if self.condition and not model_utils.has_permissions(self.condition, user):
            self.on_authorization_failure()


def requires_user(arg=None, *args, **kwargs):
    """ Require a user to be authenticated before proceeding to decorated target. May be used as
        a class decorator or method decorator.

        Usage: @requires_user OR @requires_user() (both usage forms are identical)
        Parameters:
            authenticators: identifiers for authenticators registered on the auth_manager. The
                primary authenticator on auth_manager will be used by default
            on_authentication_failure: method called on authentication failures. If one is not
                specified, behavior is derived from authenticators (redirect or 401)
            on_authorization_failure: method called on authorization failures. If one is not
                specified, response will be 403
    """
    if arg is None:
        return RequiresUser(*args, **kwargs)
    if inspect.isclass(arg):
        return RequiresUser().decorate_class(arg)  # pragma: no cover
    return RequiresUser().decorate_function(arg)


requires_permissions = RequiresPermissions
