import flask
import flask_login
from keg.db import db
import jinja2
import six

import keg_auth.cli
from keg_auth.libs.authenticators import KegAuthenticator
from keg_auth import model
from keg_auth.mail import MailManager


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
    mail_manager_cls = MailManager
    cli_group_name = 'auth'

    def __init__(self, mail_ext, blueprint='auth', user_entity='User', endpoints=None,
                 cli_group_name=None, grid_cls=None, primary_authenticator_cls=KegAuthenticator,
                 secondary_authenticators=[]):
        self.mail_ext = mail_ext
        self.blueprint_name = blueprint
        self.user_entity = user_entity
        self.endpoints = self.endpoints.copy()
        if endpoints:
            self.endpoints.update(endpoints)
        self.cli_group_name = cli_group_name or self.cli_group_name
        self.cli_group = None
        self.grid_cls = grid_cls
        self.primary_authenticator_cls = primary_authenticator_cls
        self.secondary_authenticators = secondary_authenticators
        self.authenticators = {}
        self.menus = dict()
        self._model_initialized = False
        self._authenticators_initialized = False

    def init_app(self, app):
        self.init_model(app)
        self.init_config(app)
        self.init_managers(app)
        self.init_cli(app)
        self.init_jinja(app)
        self.init_authenticators(app)

    def init_config(self, app):
        _cc_kwargs = dict(schemes=['bcrypt', 'pbkdf2_sha256'], deprecated='auto')
        app.config.setdefault('PASSLIB_CRYPTCONTEXT_KWARGS', _cc_kwargs)

        site_name = app.config.get('SITE_NAME', 'UNKNOWN')
        app.config.setdefault('KEGAUTH_EMAIL_SITE_NAME', site_name)

        site_abbr = app.config.get('SITE_ABBR', site_name)
        app.config.setdefault('KEGAUTH_EMAIL_SITE_ABBR', site_abbr)

        app.config.setdefault('KEGAUTH_BASE_TEMPLATE', 'base-page.html')
        app.config.setdefault('KEGAUTH_TOKEN_EXPIRE_MINS', 60 * 4)

        app.config.setdefault('KEGAUTH_CLI_USER_ARGS', ['email'])

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
        app.auth_mail_manager = self.mail_manager_cls(self.mail_ext)

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
        from passlib.pwd import genword
        user_kwargs.setdefault('password', genword(entropy='secure'))
        user_class = self.get_user_entity()
        user = user_class(**user_kwargs)
        user.token_generate()
        db.session.add(user)
        db.session.flush()
        flask.current_app.auth_mail_manager.send_new_user(user)

        # use add + commit here instead of user_class.add() above so the user isn't actually
        # committed if mail isn't set.
        db.session.commit()
        return user

    def verify_account_url(self, user):
        return self.url_for(
            'verify-account', user_id=user.id, token=user._token_plain, _external=True)

    def reset_password_url(self, user):
        return self.url_for(
            'reset-password', user_id=user.id, token=user._token_plain, _external=True)

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
