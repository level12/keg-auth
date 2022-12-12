import arrow
import flask
import flask_login
import jinja2
import sqlalchemy as sa
from blazeutils import tolist
from keg.db import db
from keg.signals import db_init_post, init_complete
from webgrid.renderers import render_html_attributes

import keg_auth.cli
from keg_auth import model
from keg_auth.libs.authenticators import (
    DefaultPasswordPolicy,
    KegAuthenticator,
    OAuthAuthenticator,
)

DEFAULT_CRYPTO_SCHEMES = ('bcrypt', 'pbkdf2_sha256',)


class AuthManager(object):
    """Set up an auth management extension

    Main manager for keg-auth authentication/authorization functions, and provides a central
    location and handle on the flask app to access CLI setup, navigation, authenticators, etc.

    :param mail_manager: AuthMailManager instance used for mail functions. Can be None.
    :param blueprint: name to use for the blueprint containing auth views
    :param endpoints: dict of overrides to auth view endpoints
    :param cli_group_name: name of the CLI group under which auth commands appear
    :param grid_cls: webgrid class to serve as a base class to auth CRUD grids
    :param login_authenticator: login authenticator class used by login view
        default: KegAuthenticator
    :param request_loaders: registered loaders used for loading a user at request time from
        information not contained in the session (e.g. with an authorization header token).
        Can be scalar or an iterable
    :param permissions: permission strings defined for the app, which will be synced to the
        database on app init. Can be a single string or an iterable
    :param entity_registry: EntityRegistry instance on which User, Group, etc. are registered
    :param password_policy_cls: A PasswordPolicy class to check password requirements in
        forms and CLI
    """
    endpoints = {
        'forgot-password': '{blueprint}.forgot-password',
        'reset-password': '{blueprint}.reset-password',
        'change-password': '{blueprint}.change-password',
        'login': '{blueprint}.login',
        'logout': '{blueprint}.logout',
        'after-login': '{blueprint}.after-login',
        'after-logout': '{blueprint}.login',
        'after-forgot': '{blueprint}.login',
        'after-reset': '{blueprint}.login',
        'verify-account': '{blueprint}.verify-account',
        'after-verify-account': '{blueprint}.login',
        'oauth-login': '{blueprint}.oauth-login',
        'oauth-authorize': '{blueprint}.oauth-authorize',
    }
    cli_group_name = 'auth'

    def __init__(self, mail_manager=None, blueprint='auth', endpoints=None,
                 cli_group_name=None, grid_cls=None, login_authenticator=KegAuthenticator,
                 request_loaders=None, permissions=None, entity_registry=None,
                 oauth_authenticator=OAuthAuthenticator,
                 password_policy_cls=DefaultPasswordPolicy):
        self.mail_manager = mail_manager
        self.blueprint_name = blueprint
        self.entity_registry = entity_registry
        self.password_policy_cls = password_policy_cls
        self.endpoints = self.endpoints.copy()
        if endpoints:
            self.endpoints.update(endpoints)
        self.cli_group_name = cli_group_name or self.cli_group_name
        self.cli_group = None
        self.grid_cls = grid_cls
        self.login_authenticator_cls = login_authenticator
        self.oauth_authenticator_cls = oauth_authenticator
        self.request_loader_cls = tolist(request_loaders or [])
        self.request_loaders = dict()
        self.menus = dict()
        self.permissions = tolist(permissions or [])
        self._model_initialized = False
        self._loaders_initialized = False
        self._signal_handlers = []

    def init_app(self, app):
        """Inits KegAuth as a flask extension on the given app."""
        self.init_model(app)
        self.init_config(app)
        self.init_managers(app)
        self.init_cli(app)
        self.init_jinja(app)
        self.init_loaders(app)
        self.init_permissions(app)
        self.init_custom_csrf(app)

        self.fix_testing_teardown(app)

    def init_config(self, app):
        """Provide app config defaults for crypto, mail, logins, etc."""
        _cc_kwargs = dict(schemes=DEFAULT_CRYPTO_SCHEMES, deprecated='auto')
        app.config.setdefault('PASSLIB_CRYPTCONTEXT_KWARGS', _cc_kwargs)

        # config flag controls email ops such as sending verification emails, etc.
        # Note: model mixin must be in place for email
        app.config.setdefault('KEGAUTH_EMAIL_OPS_ENABLED', self.mail_manager is not None)

        site_name = app.config.get('SITE_NAME', 'UNKNOWN')
        app.config.setdefault('KEGAUTH_EMAIL_SITE_NAME', site_name)

        site_abbr = app.config.get('SITE_ABBR', site_name)
        app.config.setdefault('KEGAUTH_EMAIL_SITE_ABBR', site_abbr)

        app.config.setdefault('KEGAUTH_CRUD_INCLUDE_TITLE', True)
        app.config.setdefault('KEGAUTH_TEMPLATE_TITLE_VAR', 'page_title')
        app.config.setdefault('KEGAUTH_TOKEN_EXPIRE_MINS', 60 * 4)
        app.config.setdefault('KEGAUTH_LOGOUT_CLEAR_SESSION', True)

        app.config.setdefault('KEGAUTH_CLI_USER_ARGS', ['email'])

        # HTTP methods to ignore during auth checks. This can be useful for excluding
        # methods like OPTIONS during front-end API requests, for CORS compatibility.
        app.config.setdefault('KEGAUTH_HTTP_METHODS_EXCLUDED', [])

        # Set the login target for the redirect authenticator
        app.config.setdefault('KEGAUTH_REDIRECT_LOGIN_TARGET', None)

        # OAuth profiles
        app.config.setdefault('KEGAUTH_OAUTH_PROFILES', [])

        # Attempt lockout parameters.
        # - Enabled: default True, turns on attempt limits and requires the attempt entity.
        # - Limit: maximum number of attempts within the timespan.
        # - Timespan: number of seconds in which the limit can be reached.
        # - Lockout: number of seconds until an attempt can be made after the limit is reached.
        # - KEGAUTH_ATTEMPT_IP_LIMIT: base locking on IP address as well as input
        app.config.setdefault('KEGAUTH_ATTEMPT_LIMIT_ENABLED', True)
        app.config.setdefault('KEGAUTH_ATTEMPT_LIMIT', 15)
        app.config.setdefault('KEGAUTH_ATTEMPT_TIMESPAN', 600)  # 10 minutes
        app.config.setdefault('KEGAUTH_ATTEMPT_LOCKOUT', 3600)  # 1 hour
        app.config.setdefault('KEGAUTH_ATTEMPT_IP_LIMIT', True)
        # Lockout parameters may also be set for specific views (login, forgot, reset). If these
        # specific values are not set, the generic ATTEMPT values will be used.
        # app.config.setdefault('KEGAUTH_LOGIN_ATTEMPT_LIMIT', 3)
        # app.config.setdefault('KEGAUTH_LOGIN_ATTEMPT_TIMESPAN', 3600)  # 1 hour
        # app.config.setdefault('KEGAUTH_LOGIN_ATTEMPT_LOCKOUT', 3600)  # 1 hour
        # app.config.setdefault('KEGAUTH_FORGOT_ATTEMPT_LIMIT', 5)
        # app.config.setdefault('KEGAUTH_FORGOT_ATTEMPT_TIMESPAN', 3600)  # 1 hour
        # app.config.setdefault('KEGAUTH_FORGOT_ATTEMPT_LOCKOUT', 3600)  # 1 hour
        # app.config.setdefault('KEGAUTH_RESET_ATTEMPT_LIMIT', 1)
        # app.config.setdefault('KEGAUTH_RESET_ATTEMPT_TIMESPAN', 86400)  # 24 hours
        # app.config.setdefault('KEGAUTH_RESET_ATTEMPT_LOCKOUT', 86400)  # 24 hours

    def init_cli(self, app):
        """Add a CLI group for auth."""
        keg_auth.cli.add_cli_to_app(app, self.cli_group_name,
                                    user_args=app.config.get('KEGAUTH_CLI_USER_ARGS'))

    def init_jinja(self, app):
        """Set up app jinja loader to use keg-auth templates, select2, etc."""
        loader = jinja2.ChoiceLoader([
            app.jinja_loader,
            jinja2.PackageLoader('keg_auth', 'templates'),
            # Get access to form generation templates from Keg Elements.
            jinja2.PackageLoader('keg_elements', 'templates'),
        ])
        app.jinja_loader = loader
        app.context_processor(lambda: {
            'auth_manager': self,
            'use_select2': app.config.get('KEGAUTH_USE_SELECT2'),
        })
        app.jinja_env.filters['html_attributes'] = app.jinja_env.filters.get(
            'html_attributes', render_html_attributes
        )

    def init_model(self, app):
        """Set up the entity registry for all auth objects."""
        if not self._model_initialized:
            model.initialize_mappings(registry=self.entity_registry)
            model.initialize_events(registry=self.entity_registry)
            self._model_initialized = True

    def init_managers(self, app):
        """Place this extension on the app for reference, and onfigure flask-login."""
        app.auth_manager = self

        app.login_manager = login_manager = flask_login.LoginManager()
        login_manager.user_loader(self.user_loader)
        if app.testing:
            login_manager.request_loader(self.test_request_loader)
        login_manager.login_view = self.endpoint('login')
        login_manager.init_app(app)

    def init_loaders(self, app):
        """Initialize user session loaders."""
        if self._loaders_initialized:
            return

        self.login_authenticator = self.login_authenticator_cls(app)

        if app.config.get('KEGAUTH_OAUTH_PROFILES'):
            self.oauth_authenticator = OAuthAuthenticator(app)

        for loader_cls in self.request_loader_cls:
            self.request_loaders[loader_cls.get_identifier()] = loader_cls(app)

        self._loaders_initialized = True

    def init_permissions(self, app):
        """Configure database with the defined set of permissions.

        Synchronizes permission records in the database with those defined in the app. Ensures
        the sync method is called in the proper place during test runs, when the database is not
        fully available and set up at extension-loading time.
        """
        from keg_auth.model.entity_registry import RegistryError

        if not self.entity_registry:
            return

        try:
            Permission = self.entity_registry.permission_cls
        except RegistryError:
            return

        # The tricky thing here is that the db may not be ready. Normal app startup should
        # expect it at this point, but test setup may not have initialized tables by now.
        # So, connect it to the test signal, then try to call it, and trap the exception
        def sync_permissions(app):
            with app.app_context():
                db_permissions = db.session.query(Permission).all()

                # sync permission presence
                desired_tokens = set(
                    tolist(perm)[0] for perm in app.auth_manager.permissions
                )
                current_tokens = {
                    permission.token for permission in db_permissions
                }
                for permission in desired_tokens - current_tokens:
                    db_permissions.append(Permission.add(token=permission, _commit=False))
                for permission in current_tokens - desired_tokens:
                    Permission.query.filter_by(token=permission).delete()

                # sync permission description
                permission_descriptions = dict(
                    [perm for perm in app.auth_manager.permissions
                     if isinstance(perm, (list, tuple))]
                )
                for db_permission in db_permissions:
                    if (
                        db_permission.token in permission_descriptions
                        and db_permission.description
                            != permission_descriptions[db_permission.token]
                    ):
                        db_permission.description = permission_descriptions[db_permission.token]
                    elif (
                        db_permission.token not in permission_descriptions
                        and db_permission.description
                    ):
                        db_permission.description = None

                try:
                    db.session.commit()
                except sa.exc.IntegrityError as exc:
                    # We have a possible race condition here, in that if another app process starts
                    # while we are computing permission sync, we could get an integrity error.
                    # Check that it is a unique exception, but note that we're not able to check
                    # the constraint name here (too many assumptions to be made).
                    from keg_elements.db.utils import validate_unique_exc
                    if not validate_unique_exc(exc):
                        raise

        # store the connected method somewhere, so we don't lose it with current function scope
        self._sync_permissions = db_init_post.connect(sync_permissions)

        try:
            # During normal app startup with models present, this should work just fine. However,
            # if we are running tests where the model is cleaned/restored during test setup,
            # that process completes after this step. So, we need to trap the ensuing exception,
            # and let the testing signal do the setup.
            # syncing permissions during testing was causing some db session issues.
            if not app.testing:
                sync_permissions(app)
        except sa.exc.ProgrammingError as exc:
            if 'permissions' not in str(exc):
                raise

    def init_custom_csrf(self, app):
        @init_complete.connect
        def handle_custom_csrf(app):
            if 'csrf' not in app.extensions:
                return
            for endpoint_key in self.endpoints.keys():
                endpoint = self.endpoint(endpoint_key)
                view_obj = app.view_functions.get(endpoint)
                if (
                    not hasattr(view_obj, 'view_class')
                    or not hasattr(view_obj.view_class, 'auth_manager_key')
                    or not hasattr(view_obj.view_class, 'responder_key')
                ):
                    # only support auth-responded class views for this right now
                    continue
                dest = f"{view_obj.__module__}.{view_obj.__name__}"
                authenticator_cls = getattr(self, f'{view_obj.view_class.auth_manager_key}_cls')
                responder_cls = authenticator_cls.responder_cls.get(
                    view_obj.view_class.responder_key
                )
                if getattr(responder_cls, '_csrf_custom_handling', False):
                    app.extensions['csrf'].exempt(dest)

        # persist a reference to this method for the signal to call
        self._signal_handlers.append(handle_custom_csrf)

    def validate_permission_set(self, permissions):
        defined_tokens = set(
            tolist(perm)[0] for perm in self.permissions
        )
        undefined_tokens = set(tolist(permissions)) - defined_tokens
        if undefined_tokens:
            raise Exception(f'permission(s) {undefined_tokens} not specified in the auth manager')

    def add_navigation_menu(self, name, menu):
        """Create a navigation menu that may be referenced with the given name."""
        self.menus[name] = menu

    def endpoint(self, ident):
        """Return an auth endpoint on the configured blueprint."""
        return self.endpoints[ident].format(blueprint=self.blueprint_name)

    def url_for(self, ident, **kwargs):
        """Generate the URL for the endpoint identified by `ident`."""
        return flask.url_for(self.endpoint(ident), **kwargs)

    def user_loader(self, session_key):
        """Fetch a user record via session key."""
        user_class = self.entity_registry.user_cls
        return user_class.get_by(session_key=str(session_key))

    def user_by_id(self, user_id):
        """Fetch a user record via ID."""
        user_class = self.entity_registry.user_cls
        return user_class.get_by(id=user_id)

    def test_request_loader(self, request):
        """ Load a user from a request when testing. This gives a nice API for test clients to
            be logged in, rather than expecting all tests to set up an actual session.

            See `keg_auth.testing.AuthTestApp` for a webtest wrapper using this loader.
        """
        session_key = request.environ.get('TEST_USER_ID')
        if session_key is None:
            return
        return self.user_loader(session_key)

    def create_user_cli(self, extra_args=None, **kwargs):
        """ A thin layer between the cli and `create_user()` to transform the cli args
            into what the User entity expects for fields.

            For example, if you had a required `name` field on your User entity, then you could do
            something like::

                $ yourkegapp auth create-user john.smith@example.com "John Smith"

            Then this method would get overriden in a sub-class like:

                def create_user_cli(self, email, extra_args):
                    user_kwargs = dict(email=email, name=extra_args[0])
                    return self.create_user(user_kwargs)
        """
        # By default, we assume no extra arguments are used
        user_kwargs = kwargs
        return self.create_user(user_kwargs)

    def create_user(self, user_kwargs, _commit=True):
        """Create a new user record and optionally persist to the database.

        :param user_kwargs: dict of values to construct the User record. Special arg is
            `mail_enabled`, which will be popped out.
        :param _commit: option for persisting record to database. Default True.
        """
        mail_enabled = user_kwargs.pop('mail_enabled', True)
        from passlib.pwd import genword
        user_kwargs.setdefault('password', genword(entropy='secure'))
        user_class = self.entity_registry.user_cls
        user = user_class(**user_kwargs)
        db.session.add(user)
        db.session.flush()

        # generate the token AFTER flush, because the token may depend on things like timestamps
        # which may not be available earlier
        user.token_generate()

        if (
            mail_enabled
            and self.mail_manager
            and not self.login_authenticator.is_domain_excluded(user.username)
        ):
            self.mail_manager.send_new_user(user)

        # use add + commit here instead of user_class.add() above so the user isn't actually
        # committed if mail isn't sent.
        if _commit:
            db.session.commit()
        return user

    def get_request_loader(self, identifier):
        """Returns a registered request loader, keyed by its identifier."""
        return self.request_loaders.get(identifier)

    def resend_verification_email(self, user_id):
        """Generate a fresh token and send the account verification email."""
        user = self.user_by_id(user_id)
        if not self.mail_manager:
            raise Exception("Tried to resend verification email, but email is not setup.")
        # ensure the user object has a fresh token
        user.token_generate()
        self.mail_manager.send_new_user(user)

    def fix_testing_teardown(self, app):
        """ Needed until https://github.com/level12/keg/issues/90 is fixed & released. """
        if not app.config.get('TESTING', False):
            return

        version = tuple(map(lambda x: int(x), flask_login.__version__.split('.')))

        if version < (0, 6, 2):
            return

        @app.teardown_request
        def cleanup_user_cache(error):
            if '_login_user' in flask.g:
                del flask.g._login_user


# ensure that any manager-attached menus are reset for auth requirements on login/logout
def refresh_session_menus(app, user):
    for menu in app.auth_manager.menus.values():
        menu.clear_authorization(user.get_id())


def update_last_login(app, user):
    user.last_login_utc = arrow.utcnow()
    db.session.commit()


def on_login(app, user):
    refresh_session_menus(app, user)
    update_last_login(app, user)


def clear_session(app, user):
    if app.config.get('KEGAUTH_LOGOUT_CLEAR_SESSION'):
        flask.session.clear()


flask_login.signals.user_logged_in.connect(on_login)
flask_login.signals.user_logged_out.connect(refresh_session_menus)
flask_login.signals.user_logged_out.connect(clear_session)
