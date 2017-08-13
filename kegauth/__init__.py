import flask
import flask_login
from keg.db import db
import jinja2

from kegauth.mail import MailManager


class AuthManager(object):
    endpoints = {
        'forgot-password': '{blueprint}.forgot-password',
        'reset-password': '{blueprint}.reset-password',
        'change-password': '{blueprint}.change-password',
        'login': '{blueprint}.login',
        'after-login': '{blueprint}.after-login',
        'after-forgot': '{blueprint}.login',
        'after-reset': '{blueprint}.login',
    }
    mail_manager_cls = MailManager

    def __init__(self, mail_ext, blueprint='auth', user_entity='User', endpoints=None):
        self.mail_ext = mail_ext
        self.blueprint_name = blueprint
        self.user_entity = 'User'
        self.endpoints = self.endpoints.copy()
        if endpoints:
            self.endpoints.update(endpoints)

    def init_app(self, app):
        self.init_config(app)
        self.init_managers(app)
        self.init_jinja(app)

        @app.teardown_request
        def cleanup_csrf_cache(error):
            # Needed until https://github.com/lepture/flask-wtf/issues/301 is fixed & released.
            if 'csrf_token' in flask.g:
                del flask.g.csrf_token

    def init_config(self, app):
        _cc_kwargs = dict(schemes=['bcrypt', 'pbkdf2_sha256'], deprecated='auto')
        app.config.setdefault('PASSLIB_CRYPTCONTEXT_KWARGS', _cc_kwargs)
        app.config.setdefault('KEGAUTH_BASE_TEMPLATE', 'base-page.html')
        site_name = app.config.get('SITE_NAME', 'UNKNOWN')
        app.config.setdefault('KEGAUTH_EMAIL_SITE_NAME', site_name)
        site_abbr = app.config.get('SITE_ABBR', site_name)
        app.config.setdefault('KEGAUTH_EMAIL_SITE_ABBR', site_abbr)
        app.config.setdefault('KEGAUTH_TOKEN_EXPIRE_MINS', 60 * 4)

    def init_jinja(self, app):
        loader = jinja2.ChoiceLoader([
            app.jinja_loader,
            jinja2.PackageLoader('kegauth', 'templates'),
            # Get access to form generation templates from Keg Elements.
            jinja2.PackageLoader('keg_elements', 'templates'),
        ])
        app.jinja_loader = loader
        app.context_processor(lambda: {'auth_manager': self})

    def init_managers(self, app):
        app.auth_manager = self
        app.auth_mail_manager = self.mail_manager_cls(self.mail_ext)

        app.login_manager = login_manager = flask_login.LoginManager()
        login_manager.user_loader(lambda user_id: self.user_loader(user_id))
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
