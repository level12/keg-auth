import flask
import flask_login
from six.moves import urllib

from keg_auth import forms

try:
    import flask_jwt_extended
except ImportError:
    pass  # pragma: no cover

try:
    import ldap
except ImportError:
    pass  # pragma: no cover


class UserNotFound(Exception):
    pass


class UserInactive(Exception):
    def __init__(self, user):
        self.user = user


class UserInvalidAuth(Exception):
    def __init__(self, user):
        self.user = user


class RequestLoader(object):
    """ Generic loader interface for determining if a user should be logged in"""

    def __init__(self, app):
        self.user_ent = app.auth_manager.entity_registry.user_cls

    @classmethod
    def get_identifier(cls):
        return cls.__name__.lower().replace('requestloader', '')


class LoginManager(object):
    authentication_failure_redirect = True
    responder_cls = None

    def __init__(self, app):
        self.responder = self.responder_cls()
        self.responder.parent = self
        self.user_ent = app.auth_manager.entity_registry.user_cls

    def __call__(self, *args, **kwargs):
        method_name = flask.request.method.lower()
        method_obj = getattr(self.responder, method_name, None)
        if not method_obj:
            raise NotImplementedError(method_name)
        resp = method_obj(*args, **kwargs)

        return resp or flask.render_template(
            self.responder.template_name, **self.responder.template_args
        )


class ViewResponder(object):
    template_name = None

    def __init__(self):
        self.template_args = {}

    def assign(self, key, value):
        self.template_args[key] = value


class PasswordFormViewResponder(ViewResponder):
    template_name = 'keg_auth/login.html'
    page_title = 'Log In'
    flash_form_error = 'The form has errors, please see below.', 'error'
    flash_success = 'Login successful.', 'success'
    flash_invalid_password = 'Invalid password.', 'error'
    flash_invalid_user = 'No user account matches: {}', 'error'
    flash_unverified_user = 'The user account "{}" has an unverified email address.  Please check' \
        ' your email for a verification link from this website.  Or, use the "forgot' \
        ' password" link to verify the account.', 'error'
    flash_disabled_user = 'The user account "{}" has been disabled.  Please contact this' \
        ' site\'s administrators for more information.', 'error'

    @property
    def form_cls(self):
        return forms.login_form()

    @staticmethod
    def is_safe_url(target):
        """Returns `True` if the target is a valid URL for redirect"""
        # from http://flask.pocoo.org/snippets/62/
        ref_url = urllib.parse.urlparse(flask.request.host_url)
        test_url = urllib.parse.urlparse(urllib.parse.urljoin(flask.request.host_url, target))
        return (
            test_url.scheme in ('http', 'https') and
            ref_url.netloc == test_url.netloc
        )

    def on_form_error(self, form):
        flask.flash(*self.flash_form_error)

    def on_form_valid(self, form):
        try:
            user = self.parent.verify_user(login_id=form.login_id.data, password=form.password.data)

            # User is active and password is verified
            return self.on_success(user)
        except UserNotFound:
            self.on_invalid_user(form, 'login_id')
        except UserInactive as exc:
            self.on_inactive_user(exc.user)
        except UserInvalidAuth:
            self.on_invalid_password()

    def on_invalid_password(self):
        flask.flash(*self.flash_invalid_password)

    def on_invalid_user(self, form, field):
        message, category = self.flash_invalid_user
        val = getattr(form, field).data
        flask.flash(message.format(val), category)

    def on_inactive_user(self, user):
        if flask.current_app.auth_manager.mail_manager and not user.is_verified:
            message, category = self.flash_unverified_user
            flask.flash(message.format(user.email), category)
        if not user.is_enabled:
            self.on_disabled_user(user)

    def on_success(self, user):
        flask_login.login_user(user)
        flask.flash(*self.flash_success)

        # support Flask-Login "next" parameter
        next_parameter = flask.request.values.get('next')
        if flask.current_app.config.get('USE_SESSION_FOR_NEXT'):
            next_parameter = flask.session.get('next')
        if next_parameter and self.is_safe_url(next_parameter):
            redirect_to = next_parameter
        else:
            redirect_to = flask.current_app.auth_manager.url_for('after-login')

        return flask.redirect(redirect_to)

    def on_disabled_user(self, user):
        message, category = self.flash_disabled_user
        flask.flash(message.format(user.display_value), category)

    def assign_template_vars(self, form):
        self.assign('form', form)
        self.assign('form_action_text', self.page_title)
        self.assign('page_title', self.page_title)
        self.assign('page_heading', self.page_title)

    def get(self):
        form = self.form_cls()
        self.assign_template_vars(form)

    def post(self):
        form = self.form_cls()
        if form.validate():
            resp = self.on_form_valid(form)
            if resp is not None:
                return resp
        else:
            self.on_form_error(form)

        self.assign_template_vars(form)


class PasswordAuthenticatorMixin(object):
    """ Username/password authenticators will need a way to verify a user is valid
        prior to making it the current user in flask login """
    responder_cls = PasswordFormViewResponder

    def verify_user(self, login_id=None, password=None):
        raise NotImplementedError

    def verify_password(self, user, password):
        return NotImplementedError


class TokenLoaderMixin(object):
    """ Token authenticators will need a way to generate an access token, which will then be
        loaded in the request to log a user into flask-login """
    authentication_failure_redirect = False

    def create_access_token(self, user):
        raise NotImplementedError


class KegAuthenticator(PasswordAuthenticatorMixin, LoginManager):
    def verify_user(self, login_id=None, password=None):
        user = self.user_ent.query.filter_by(username=login_id).one_or_none()

        if not user:
            raise UserNotFound
        if not user.is_active:
            raise UserInactive(user)
        if password and not self.verify_password(user, password):
            raise UserInvalidAuth(user)

        return user

    def verify_password(self, user, password):
        return user.password == password


class LdapAuthenticator(KegAuthenticator):
    def verify_password(self, user, password):
        """
        Check the given username/password combination at the
        application's configured LDAP server. Returns `True` if
        the user authentication is successful, `False` otherwise.
        NOTE: By request, authentication can be bypassed by setting
              the KEGAUTH_LDAP_TEST_MODE configuration setting to `True`.
              When set, all authentication attempts will succeed!
        :param user:
        :param password:
        :return:
        """

        if flask.current_app.config.get('KEGAUTH_LDAP_TEST_MODE', False):
            return True

        ldap_url = flask.current_app.config.get('KEGAUTH_LDAP_SERVER_URL')
        if not ldap_url:
            raise Exception('No KEGAUTH_LDAP_SERVER_URL configured!')

        ldap_dn_format = flask.current_app.config.get('KEGAUTH_LDAP_DN_FORMAT')
        if not ldap_dn_format:
            raise Exception('No KEGAUTH_LDAP_DN_FORMAT configured!')

        session = ldap.initialize(ldap_url)

        try:
            dn = ldap_dn_format.format(user.username)
            result = session.simple_bind_s(dn, password)
            return bool(
                result and
                len(result) and
                result[0] == ldap.RES_BIND
            )
        except (ldap.INVALID_CREDENTIALS, ldap.INVALID_DN_SYNTAX):
            return False


class JwtRequestLoader(TokenLoaderMixin, RequestLoader):
    """ Authenticator for JWT tokens contained in the Authorization header.

        Requires flask-jwt-extended (`pip install keg-auth[jwt]`)"""
    def __init__(self, app):
        super(JwtRequestLoader, self).__init__(app)

        self.jwt_manager = jwt_manager = flask_jwt_extended.JWTManager()
        jwt_manager.init_app(app)

        @jwt_manager.user_identity_loader
        def user_identity_loader(user):
            """
            Serialize a user entity to the JWT token
            This method is the complement of `user_loader_callback_loader`
            """
            return user.session_key

        @jwt_manager.user_loader_callback_loader
        def user_loader_callback_loader(session_key):
            """
            Load a user entity from the JWT token
            This method is the complement of `user_identity_loader`

            Note, if user is not found or inactive, fail silently - user just won't get loaded
            """
            return self.user_ent.get_by(session_key=session_key, is_active=True)

    @staticmethod
    def get_authenticated_user():
        try:
            flask_jwt_extended.verify_jwt_in_request()
            user = flask_jwt_extended.get_current_user()
            flask_login.login_user(user)
            return user
        except flask_jwt_extended.exceptions.JWTExtendedException:
            return None

    def create_access_token(self, user):
        return flask_jwt_extended.create_access_token(user)
