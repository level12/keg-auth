from blazeutils import tolist
import flask
import flask_login
from keg.db import db
from keg.signals import db_init_post
import jinja2
import six

import keg_auth.cli
from keg_auth.libs.authenticators import KegAuthenticator
from keg_auth import model


class AuthManager(object):
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
    }
    cli_group_name = 'auth'

    def __init__(self, mail_manager=None, blueprint='auth', user_entity='User', endpoints=None,
                 cli_group_name=None, grid_cls=None, primary_authenticator_cls=KegAuthenticator,
                 secondary_authenticators=None, permissions=None):
        """Set up an auth management extension

        Main manager for keg-auth authentication/authorization functions, and provides a central
        location and handle on the flask app to access CLI setup, navigation, authenticators, etc.

        :param mail_manager: AuthMailManager instance used for mail functions. Can be None.
        :param blueprint: name to use for the blueprint containing auth views
        :param user_entity: name of the SQLAlchemy ORM entity representing a user
        :param endpoints: dict of overrides to auth view endpoints
        :param cli_group_name: name of the CLI group under which auth commands appear
        :param grid_cls: webgrid class to serve as a base class to auth CRUD grids
        :param primary_authenticator_cls: authenticator class used by login view, and for any view
            requiring a user (if the requirement does not specify authenticators)
            default: KegAuthenticator
        :param secondary_authenticators: authenticator classes initialized by this manager and
            registered by key for reference (e.g. 'jwt' for JwtAuthenticator). Can be scalar or
            an iterable
        :param permissions: permission strings defined for the app, which will be synced to the
            database on app init. Can be a single string or an iterable
        """
        self.mail_manager = mail_manager
        self.blueprint_name = blueprint
        self.user_entity = user_entity
        self.endpoints = self.endpoints.copy()
        if endpoints:
            self.endpoints.update(endpoints)
        self.cli_group_name = cli_group_name or self.cli_group_name
        self.cli_group = None
        self.grid_cls = grid_cls
        self.primary_authenticator_cls = primary_authenticator_cls
        self.secondary_authenticators = tolist(secondary_authenticators or [])
        self.authenticators = dict()
        self.menus = dict()
        self.permissions = tolist(permissions or [])
        self._model_initialized = False
        self._authenticators_initialized = False

    def init_app(self, app):
        self.init_model(app)
        self.init_config(app)
        self.init_managers(app)
        self.init_cli(app)
        self.init_jinja(app)
        self.init_authenticators(app)
        self.init_permissions(app)

    def init_config(self, app):
        _cc_kwargs = dict(schemes=['bcrypt', 'pbkdf2_sha256'], deprecated='auto')
        app.config.setdefault('PASSLIB_CRYPTCONTEXT_KWARGS', _cc_kwargs)

        # config flag controls email ops such as sending verification emails, etc.
        # Note: model mixin must be in place for email
        app.config.setdefault('KEGAUTH_EMAIL_OPS_ENABLED', self.mail_manager is not None)

        site_name = app.config.get('SITE_NAME', 'UNKNOWN')
        app.config.setdefault('KEGAUTH_EMAIL_SITE_NAME', site_name)

        site_abbr = app.config.get('SITE_ABBR', site_name)
        app.config.setdefault('KEGAUTH_EMAIL_SITE_ABBR', site_abbr)

        app.config.setdefault('KEGAUTH_BASE_TEMPLATE', 'base-page.html')
        app.config.setdefault('KEGAUTH_TOKEN_EXPIRE_MINS', 60 * 4)

        app.config.setdefault('KEGAUTH_CLI_USER_ARGS', ['email'])
        app.config.setdefault('KEGAUTH_USER_IDENT_FIELD', 'email')

    def init_cli(self, app):
        keg_auth.cli.add_cli_to_app(app, self.cli_group_name,
                                    user_args=app.config.get('KEGAUTH_CLI_USER_ARGS'))

    def init_jinja(self, app):
        loader = jinja2.ChoiceLoader([
            app.jinja_loader,
            jinja2.PackageLoader('keg_auth', 'templates'),
            # Get access to form generation templates from Keg Elements.
            jinja2.PackageLoader('keg_elements', 'templates'),
        ])
        app.jinja_loader = loader
        app.context_processor(lambda: {'auth_manager': self})

    def init_model(self, app):
        if not self._model_initialized:
            model.initialize_mappings()
            model.initialize_events()
            self._model_initialized = True

    def init_managers(self, app):
        app.auth_manager = self

        app.login_manager = login_manager = flask_login.LoginManager()
        login_manager.user_loader(self.user_loader)
        if app.testing:
            login_manager.request_loader(self.test_request_loader)
        login_manager.login_view = self.endpoint('login')
        login_manager.init_app(app)

    def init_authenticators(self, app):
        if self._authenticators_initialized:
            return

        primary = self.primary_authenticator_cls(app)
        self.authenticators['__primary__'] = primary
        self.authenticators[primary.get_identifier()] = primary

        for authenticator_cls in self.secondary_authenticators:
            self.authenticators[authenticator_cls.get_identifier()] = authenticator_cls(app)

        self._authenticators_initialized = True

    def init_permissions(self, app):
        # add permissions to the database
        from keg_auth.model.entity_registry import RegistryError, registry
        try:
            Permission = registry.permission_cls
        except RegistryError:
            return

        # The tricky thing here is that the db may not be ready. Normal app startup should
        # expect it at this point, but test setup may not have initialized tables by now.
        # So, connect it to the test signal, then try to call it, and trap the exception
        @db_init_post.connect
        def sync_permissions():
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
                [perm for perm in app.auth_manager.permissions if isinstance(perm, (list, tuple))]
            )
            for db_permission in db_permissions:
                if (
                    db_permission.token in permission_descriptions and
                    db_permission.description != permission_descriptions[db_permission.token]
                ):
                    db_permission.description = permission_descriptions[db_permission.token]
                elif (
                    db_permission.token not in permission_descriptions and
                    db_permission.description
                ):
                    db_permission.description = None

            db.session.commit()

        try:
            # This call works during normal app startup, but NOT during testing. Testing requires
            # the model to be set up first, after which we get the signal that sync_permissions
            # is attached to
            sync_permissions()
        except RuntimeError as exc:
            if 'No application found' not in str(exc):
                raise

    def add_navigation_menu(self, name, menu):
        self.menus[name] = menu

    def endpoint(self, ident):
        return self.endpoints[ident].format(blueprint=self.blueprint_name)

    def url_for(self, ident, **kwargs):
        return flask.url_for(self.endpoint(ident), **kwargs)

    def get_user_entity(self):
        return db.Model._decl_class_registry[self.user_entity]

    def user_loader(self, session_key):
        user_class = self.get_user_entity()
        return user_class.get_by(session_key=six.text_type(session_key))

    def test_request_loader(self, request):
        """ Load a user from a request when testing. This gives a nice API for test clients to
            be logged in:

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

    def create_user(self, user_kwargs):
        mail_enabled = user_kwargs.pop('mail_enabled', True)

        from passlib.pwd import genword
        user_kwargs.setdefault('password', genword(entropy='secure'))
        user_class = self.get_user_entity()
        user = user_class(**user_kwargs)
        db.session.add(user)
        db.session.flush()

        # generate the token AFTER flush, because the token may depend on things like timestamps
        # which may not be available earlier
        user.token_generate()

        if mail_enabled and self.mail_manager:
            self.mail_manager.send_new_user(user)

        # use add + commit here instead of user_class.add() above so the user isn't actually
        # committed if mail isn't set.
        db.session.commit()
        return user

    def get_authenticator(self, identifier):
        return self.authenticators.get(identifier)

    @property
    def primary_authenticator(self):
        return self.get_authenticator('__primary__')


# ensure that any manager-attached menus are reset for auth requirements on login/logout
def refresh_session_menus(app, user):
    for menu in app.auth_manager.menus.values():
        menu.clear_authorization()


flask_login.signals.user_logged_in.connect(refresh_session_menus)
flask_login.signals.user_logged_out.connect(refresh_session_menus)
