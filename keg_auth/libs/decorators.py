import inspect

import flask
import flask_login
from keg.web import validate_arguments, ArgumentValidationError, ViewArgumentError

from keg_auth.extensions import lazy_gettext as _
from keg_auth.model import utils as model_utils


class RequiresUser(object):
    """ Require a user to be authenticated before proceeding to decorated target. May be
        used as a class decorator or method decorator.

        Usage: @requires_user

        Note: if using along with a route decorator (e.g. Blueprint.route), requires_user
            should be the closest decorator to the method

        Examples:
        - @requires_user
        - @requires_user()
        - @requires_user(on_authentication_failure=lambda: flask.abort(400))
        - @requires_user(http_methods_excluded=['OPTIONS'])
    """
    def __init__(self, on_authentication_failure=None, http_methods_excluded=None):
        # defaults for these handlers are provided, but may be overridden here
        self._on_authentication_failure = on_authentication_failure
        self.http_methods_excluded = http_methods_excluded

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
            this.before_request(lambda: self.check_auth(instance=this))

        bp.__init__ = new_init
        self.store_auth_info(bp)
        return bp

    def decorate_class(self, cls):
        # when decorating a view class, all of the class's route methods will submit to the given
        #   auth. The view may already have check_auth defined, though, so make sure we still call
        #   it.
        method_name, old_method = next((
            (method_name, getattr(cls, method_name, None))
            for method_name in ['check_auth', 'dispatch_request']
            if callable(getattr(cls, method_name, None))
        ), (None, None))

        if not old_method:
            raise TypeError('Class must inherit from a Keg or Flask view')

        def new_method(*args, **kwargs):
            self.check_auth(instance=args[0])
            try:
                # validate_arguments is made for a function, not a class method
                # so we need to "trick" it by sending self here, but then
                # removing it before the bound method is called below
                pass_args, pass_kwargs = validate_arguments(old_method, args, kwargs.copy())
            except ArgumentValidationError as e:
                msg = _('Argument mismatch occurred: method=%s, missing=%s, '
                        'extra_keys=%s, extra_pos=%s.'
                        '  Arguments available: %s') % (old_method, e.missing,
                                                        e.extra, e.extra_positional,
                                                        kwargs)  # pragma: no cover
                raise ViewArgumentError(msg)  # pragma: no cover

            return old_method(*pass_args, **pass_kwargs)

        setattr(cls, method_name, new_method)

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

        # redirect if app's login manager requires it
        if flask.current_app.auth_manager.login_authenticator.authentication_failure_redirect:
            redirect_resp = flask.current_app.login_manager.unauthorized()
            flask.abort(redirect_resp)
        else:
            flask.abort(401)

    def check_auth(self, instance=None):
        methods_excluded = flask.current_app.config.get('KEGAUTH_HTTP_METHODS_EXCLUDED')
        if self.http_methods_excluded is not None:
            methods_excluded = self.http_methods_excluded
        if flask.request.method in methods_excluded:
            return

        # if flask_login has an authenticated user in session, that's who we want
        if flask_login.current_user.is_authenticated:
            return

        # no user in session right now, so we need to run request loaders to see if any match
        user = None
        for loader in flask.current_app.auth_manager.request_loaders.values():
            user = loader.get_authenticated_user()
            if user:
                break

        if not user or not user.is_authenticated:
            if instance and callable(getattr(instance, 'on_authentication_failure', None)):
                instance.on_authentication_failure()
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
        - @requires_permissions('token1', on_authorization_failure=lambda: flask.abort(404))
    """
    def __init__(self, condition, on_authentication_failure=None, on_authorization_failure=None,
                 http_methods_excluded=None):
        super(RequiresPermissions, self).__init__(
            on_authentication_failure=on_authentication_failure,
            http_methods_excluded=http_methods_excluded,
        )
        self.condition = condition
        self._on_authorization_failure = on_authorization_failure

    def store_auth_info(self, obj):
        super(RequiresPermissions, self).store_auth_info(obj)
        condition = self.condition
        if callable(condition) and isinstance(obj, type):
            # When applying to a class (usually a class view or a blueprint), we have to explicitly
            # wrap callables as static. Otherwise, when the obj class is instantiated, the function
            # will become bound, and we'll get parameter count exceptions.
            condition = staticmethod(condition)
        obj.__keg_auth_requires_permissions__ = condition

    def on_authorization_failure(self):
        if self._on_authorization_failure:
            self._on_authorization_failure()
        flask.abort(403)

    def check_auth(self, instance=None):
        super(RequiresPermissions, self).check_auth(instance=instance)

        user = flask_login.current_user
        if self.condition and not model_utils.has_permissions(self.condition, user):
            if instance and callable(getattr(instance, 'on_authorization_failure', None)):
                instance.on_authorization_failure()
            self.on_authorization_failure()


def requires_user(arg=None, *args, **kwargs):
    """ Require a user to be authenticated before proceeding to decorated target. May be used as
        a class decorator or method decorator.

        Usage: @requires_user OR @requires_user() (both usage forms are identical)

        Parameters:
            on_authentication_failure: method called on authentication failures. If one is not
                specified, behavior is derived from login manager (redirect or 401)
            on_authorization_failure: method called on authorization failures. If one is not
                specified, response will be 403
    """
    if arg is None:
        return RequiresUser(*args, **kwargs)
    if inspect.isclass(arg):
        if issubclass(arg, flask.Blueprint):
            return RequiresUser().decorate_blueprint(arg)
        return RequiresUser().decorate_class(arg)  # pragma: no cover
    return RequiresUser().decorate_function(arg)


requires_permissions = RequiresPermissions
