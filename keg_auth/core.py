from blazeutils.strings import randchars
import flask
import flask_login
from keg.db import db
import jinja2

import keg_auth.cli
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
                 cli_group_name=None):
        self.mail_ext = mail_ext
        self.blueprint_name = blueprint
        self.user_entity = user_entity
        self.endpoints = self.endpoints.copy()
        if endpoints:
            self.endpoints.update(endpoints)
        self.cli_group_name = cli_group_name or self.cli_group_name
        self._model_initialized = False

    def init_app(self, app):
        self.init_model(app)
        self.init_config(app)
        self.init_managers(app)
        self.init_cli(app)
        self.init_jinja(app)

    def init_config(self, app):
        _cc_kwargs = dict(schemes=['bcrypt', 'pbkdf2_sha256'], deprecated='auto')
        app.config.setdefault('PASSLIB_CRYPTCONTEXT_KWARGS', _cc_kwargs)

        site_name = app.config.get('SITE_NAME', 'UNKNOWN')
        app.config.setdefault('KEGAUTH_EMAIL_SITE_NAME', site_name)

        site_abbr = app.config.get('SITE_ABBR', site_name)
        app.config.setdefault('KEGAUTH_EMAIL_SITE_ABBR', site_abbr)

        app.config.setdefault('KEGAUTH_BASE_TEMPLATE', 'base-page.html')
        app.config.setdefault('KEGAUTH_TOKEN_EXPIRE_MINS', 60 * 4)

    def init_cli(self, app):
        keg_auth.cli.add_cli_to_app(app, self.cli_group_name)

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
            self._model_initialized = True

    def init_managers(self, app):
        app.auth_manager = self
        app.auth_mail_manager = self.mail_manager_cls(self.mail_ext)

        app.login_manager = login_manager = flask_login.LoginManager()
        login_manager.user_loader(self.user_loader)
        if app.testing:
            login_manager.request_loader(self.request_loader)
        login_manager.login_view = self.endpoint('login')
        login_manager.init_app(app)

    def endpoint(self, ident):
        return self.endpoints[ident].format(blueprint=self.blueprint_name)

    def url_for(self, ident, **kwargs):
        return flask.url_for(self.endpoint(ident), **kwargs)

    def get_user_entity(self):
        return db.Model._decl_class_registry[self.user_entity]

    def user_loader(self, user_id):
        user_class = self.get_user_entity()
        return user_class.query.get(user_id)

    def request_loader(self, request):
        """ Load a user from a request when testing. This gives a nice API for test clients to
            be logged in:

        """
        user_id = request.environ.get('TEST_USER_ID')
        if user_id is None:
            return
        return self.user_loader(user_id)

    def create_user_cli(self, email, extra_args):
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
        user_kwargs = dict(email=email)
        return self.create_user(user_kwargs)

    def create_user(self, user_kwargs):
        user_kwargs.setdefault('password', randchars(30))
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
