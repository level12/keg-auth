import flask
import flask_login
from keg.db import db
import jinja2


class AuthManager(object):
    endpoints = {
        'forgot-password': '{blueprint}.forgot-password',
        'login': '{blueprint}.login',
        'after-login': '{blueprint}.after-login',
    }

    def __init__(self, blueprint='auth', user_entity='User', endpoints=None):
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

    def init_jinja(self, app):
        loader = jinja2.ChoiceLoader([
            app.jinja_loader,
            jinja2.PackageLoader('kegauth', 'templates'),
            jinja2.PackageLoader('keg_elements', 'templates'),
        ])
        app.jinja_loader = loader
        app.context_processor(lambda: {'kegauth': self})

    def init_managers(self, app):
        app.auth_manager = self

        app.login_manager = flask_login.LoginManager()
        app.login_manager.user_loader = self.user_loader
        #app.login_view = self.endpoint('login')

    def endpoint(self, ident):
        return self.endpoints[ident].format(blueprint=self.blueprint_name)

    def url_for(self, ident):
        return flask.url_for(self.endpoint(ident))

    def get_user_entity(self):
        return db.Model._decl_class_registry[self.user_entity]

    def user_loader(self, user_id):
        user_class = self.get_user_entity()
        return user_class.query.get(user_id)
