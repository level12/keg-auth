from urllib.parse import urljoin, urlparse

import flask
import flask_login

from keg_auth import forms
from keg_auth.extensions import flash, lazy_gettext as _
from keg_auth.model import get_username_key

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


class LoginAuthenticator(object):
    """ Manages verification of users as well as relevant view-layer logic

        Relevant auth views (login, verification, resets, etc.) get passed through to responders
        on this layer, to process and render for the specific type of authentication happening.

        For example, a password authenticator will want a user/password login form, but other types
        like oauth may get a different form entirely (and handle resets differently, etc.).

        `responder_cls` is a key/value store for associating view keys with responder classes. If a
        view key is not present, we assume that view is not relevant to the authenticator, and the
        view itself will return 404.
    """

    authentication_failure_redirect = True
    responder_cls = {}

    def __init__(self, app):
        self.user_ent = app.auth_manager.entity_registry.user_cls
        self.responders = {}

        self.init_responders()

    def init_responders(self):
        for key, cls in self.responder_cls.items():
            self.responders[key] = cls(self)

    def get_responder(self, key):
        return self.responders.get(key)


class ViewResponder(object):
    """ View-layer logic wrapper for use in the Authenticator

        Responder should be combined with needed mixins for various functionality (forms,
        logins, etc.).

        Expected to have methods named for the request method (get, post, etc.)

        `template_name` is passed to `flask.render_template` by default
    """
    template_name = None

    def __init__(self, parent):
        self.template_args = {}
        self.parent = parent

    def assign(self, key, value):
        self.template_args[key] = value

    def render(self):
        return flask.render_template(self.template_name, **self.template_args)

    def __call__(self, *args, **kwargs):
        method_name = flask.request.method.lower()
        method_obj = getattr(self, method_name, None)
        if not method_obj:
            raise NotImplementedError(method_name)
        resp = method_obj(*args, **kwargs)

        return resp or self.render()

    def head(self):
        valid_methods = []
        for method in ('get', 'post'):
            if hasattr(self, method):
                valid_methods.append(method.upper())
        return flask.abort(405, valid_methods=valid_methods)


class UserResponderMixin(object):
    flash_invalid_user = _('No user account matches: {}'), 'error'
    flash_unverified_user = _(
        'The user account "{}" has an unverified email address.  Please check'
        ' your email for a verification link from this website.  Or, use the "forgot'
        ' password" link to verify the account.'
    ), 'error'
    flash_disabled_user = _(
        'The user account "{}" has been disabled.  Please contact this'
        ' site\'s administrators for more information.'
    ), 'error'

    def on_inactive_user(self, user):
        if flask.current_app.auth_manager.mail_manager and not user.is_verified:
            if self.flash_unverified_user:
                message, category = self.flash_unverified_user
                flash(message.format(user.email), category)
        if not user.is_enabled:
            self.on_disabled_user(user)

    def on_invalid_user(self, username):
        if self.flash_invalid_user:
            message, category = self.flash_invalid_user
            flash(message.format(username), category)

    def on_disabled_user(self, user):
        if self.flash_disabled_user:
            message, category = self.flash_disabled_user
            flash(message.format(user.display_value), category)


class LoginResponderMixin(UserResponderMixin):
    """ Wrap user authentication view-layer logic

        Flash messages, what to do when a user has been authenticated (by whatever method the
        parent authenticator uses), redirects to a safe URL after login, etc.
    """
    url = '/login'
    flash_success = _('Login successful.'), 'success'

    @staticmethod
    def is_safe_url(target):
        """Returns `True` if the target is a valid URL for redirect"""
        # from http://flask.pocoo.org/snippets/62/
        ref_url = urlparse(flask.request.host_url)
        test_url = urlparse(urljoin(flask.request.host_url, target))
        return (
            test_url.scheme in ('http', 'https')
            and ref_url.netloc == test_url.netloc
        )

    def on_success(self, user):
        flask_login.login_user(user)
        if self.flash_success:
            flash(*self.flash_success)

        # support Flask-Login "next" parameter
        next_parameter = flask.request.values.get('next')
        if flask.current_app.config.get('USE_SESSION_FOR_NEXT'):
            next_parameter = flask.session.get('next')
        if next_parameter and self.is_safe_url(next_parameter):
            redirect_to = next_parameter
        else:
            redirect_to = flask.current_app.auth_manager.url_for('after-login')

        return flask.redirect(redirect_to)


class FormResponderMixin(object):
    """ Wrap form usage for auth responders, contains GET and POST handlers"""
    flash_form_error = _('The form has errors, please see below.'), 'error'
    form_cls = None
    page_title = None

    def on_form_error(self, form):
        if self.flash_form_error:
            flash(*self.flash_form_error)

    def on_form_valid(self, form):
        raise NotImplementedError  # pragma: no cover

    def assign_template_vars(self, form):
        self.assign('form', form)
        self.assign('form_action_text', self.page_title)
        self.assign('page_title', self.page_title)
        self.assign('page_heading', self.page_title)

    def get(self, *args, **kwargs):
        form = self.form_cls()
        self.assign_template_vars(form)

    def post(self, *args, **kwargs):
        form = self.form_cls()
        if form.validate():
            resp = self.on_form_valid(form)
            if resp is not None:
                return resp
        else:
            self.on_form_error(form)

        self.assign_template_vars(form)


class PasswordSetterResponderBase(FormResponderMixin, ViewResponder):
    """ Base logic for resetting passwords and verifying accounts via token"""
    form_cls = forms.SetPassword
    template_name = 'keg_auth/set-password.html'
    flash_invalid_token = _(
        'Authentication token was invalid or expired.  Please fill out the'
        ' form below to get a new token.'
    ), 'error'

    def __call__(self, *args, **kwargs):
        if not flask.current_app.auth_manager.mail_manager:
            flask.abort(404)

        self.user_loader(kwargs.get('user_id'))
        self.token = kwargs.get('token')
        self.pre_method()

        return super(PasswordSetterResponderBase, self).__call__(*args, **kwargs)

    def flash_and_redirect(self, flash_parts, auth_ident):
        if flash_parts:
            flash(*flash_parts)
        redirect_to = flask.current_app.auth_manager.url_for(auth_ident)
        flask.abort(flask.redirect(redirect_to))

    def user_loader(self, user_id):
        user_ent = flask.current_app.auth_manager.entity_registry.user_cls
        self.user = user_ent.query.get(user_id)
        if not self.user:
            flask.abort(404)

    def pre_method(self):
        if not self.user.token_verify(self.token):
            resp = self.on_invalid_token()
            # In case on_invalid_token() is replaced and it accidently fails to return a value
            # make sure we change that to a generic 400.
            flask.abort(resp or 400)

    def on_form_valid(self, form):
        new_password = form.password.data
        self.user.change_password(self.token, new_password)
        self.flash_and_redirect(self.flash_success, self.on_success_endpoint)

    def on_invalid_token(self):
        self.flash_and_redirect(self.flash_invalid_token, 'forgot-password')

    def assign_template_vars(self, form):
        super(PasswordSetterResponderBase, self).assign_template_vars(form)
        self.assign('submit_button_text', self.submit_button_text)


class ResetPasswordViewResponder(PasswordSetterResponderBase):
    """ Responder for resetting passwords via token on keg-auth logins"""
    url = '/reset-password/<int:user_id>/<token>'
    page_title = _('Complete Password Reset')
    submit_button_text = _('Change Password')
    flash_success = _('Password changed.  Please use the new password to login below.'), 'success'
    on_success_endpoint = 'after-reset'


class VerifyAccountViewResponder(PasswordSetterResponderBase):
    """ Responder for verifying users via email token for keg-auth logins"""
    url = '/verify-account/<int:user_id>/<token>'
    page_title = _('Verify Account & Set Password')
    submit_button_text = _('Verify & Set Password')
    flash_success = _('Account verified & password set.  Please use the new password to login'
                      ' below.'), 'success'
    on_success_endpoint = 'after-verify-account'


class PasswordFormViewResponder(LoginResponderMixin, FormResponderMixin, ViewResponder):
    """ Master responder for username/password-style logins, using a login form"""
    template_name = 'keg_auth/login.html'
    page_title = _('Log In')
    flash_invalid_password = _('Invalid password.'), 'error'

    @property
    def form_cls(self):
        return forms.login_form()

    def on_form_valid(self, form):
        try:
            user = self.parent.verify_user(login_id=form.login_id.data, password=form.password.data)

            # User is active and password is verified
            return self.on_success(user)
        except UserNotFound:
            self.on_invalid_user(form.login_id.data)
        except UserInactive as exc:
            self.on_inactive_user(exc.user)
        except UserInvalidAuth:
            self.on_invalid_password()

    def on_invalid_password(self):
        if self.flash_invalid_password:
            flash(*self.flash_invalid_password)


class ForgotPasswordViewResponder(UserResponderMixin, FormResponderMixin, ViewResponder):
    """ Master responder for keg-integrated logins, using an email form"""
    url = '/forgot-password'
    form_cls = forms.ForgotPassword
    page_title = _('Initiate Password Reset')
    template_name = 'keg_auth/forgot-password.html'
    flash_success = _('Please check your email for the link to change your password.'), 'success'

    def __call__(self, *args, **kwargs):
        if not flask.current_app.auth_manager.mail_manager:
            flask.abort(404)

        return super(ForgotPasswordViewResponder, self).__call__(*args, **kwargs)

    def on_form_valid(self, form):
        try:
            user = self.parent.verify_user(login_id=form.email.data, allow_unverified=True)

            # User is active, take action to initiate password reset
            return self.on_success(user)
        except UserNotFound:
            self.on_invalid_user(form.email.data)
        except UserInactive as exc:
            self.on_disabled_user(exc.user)

    def on_success(self, user):
        self.send_email(user)
        if self.flash_success:
            flash(*self.flash_success)
        redirect_to = flask.current_app.auth_manager.url_for('after-forgot')
        return flask.redirect(redirect_to)

    def send_email(self, user):
        user.token_generate()
        flask.current_app.auth_manager.mail_manager.send_reset_password(user)


class LogoutViewResponder(ViewResponder):
    url = '/logout'
    flash_success = _('You have been logged out.'), 'success'

    def get(self):
        flask_login.logout_user()
        if self.flash_success:
            flash(*self.flash_success)
        redirect_to = flask.current_app.auth_manager.url_for('after-logout')
        flask.abort(flask.redirect(redirect_to))


class PasswordAuthenticatorMixin(object):
    """ Username/password authenticators will need a way to verify a user is valid
        prior to making it the current user in flask login """
    responder_cls = {
        'login': PasswordFormViewResponder
    }

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


class KegAuthenticator(PasswordAuthenticatorMixin, LoginAuthenticator):
    """ Uses username/password authentication with a login form, validates against keg-auth db"""
    responder_cls = {
        'login': PasswordFormViewResponder,
        'forgot-password': ForgotPasswordViewResponder,
        'reset-password': ResetPasswordViewResponder,
        'verify-account': VerifyAccountViewResponder,
        'logout': LogoutViewResponder,
    }

    def verify_user(self, login_id=None, password=None, allow_unverified=False):
        user = self.user_ent.query.filter_by(username=login_id).one_or_none()

        if not user:
            raise UserNotFound
        if not allow_unverified and not user.is_active:
            raise UserInactive(user)
        if allow_unverified and not user.is_enabled:
            raise UserInactive(user)
        if password and not self.verify_password(user, password):
            raise UserInvalidAuth(user)

        return user

    def verify_password(self, user, password):
        return user.password == password


class LdapAuthenticator(KegAuthenticator):
    """ Uses username/password authentication with a login form, validates against LDAP host

        Most responder types won't be relevant here.
    """
    def verify_user(self, login_id=None, password=None):
        user = self.user_ent.query.filter_by(username=login_id).one_or_none()

        if not user:
            username_key = get_username_key(self.user_ent)
            user = self.user_ent.add(**{username_key: login_id})
        if password and not self.verify_password(user, password):
            raise UserInvalidAuth(user)

        return user

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
            raise Exception(_('No KEGAUTH_LDAP_SERVER_URL configured!'))

        ldap_dn_format = flask.current_app.config.get('KEGAUTH_LDAP_DN_FORMAT')
        if not ldap_dn_format:
            raise Exception(_('No KEGAUTH_LDAP_DN_FORMAT configured!'))

        def ldap_bind(server_url):
            session = ldap.initialize(server_url)

            try:
                dn = ldap_dn_format.format(user.username)
                result = session.simple_bind_s(dn, password)
                del session
                return bool(
                    result
                    and len(result)
                    and result[0] == ldap.RES_BIND
                )
            except (ldap.INVALID_CREDENTIALS, ldap.INVALID_DN_SYNTAX):
                return False

        if isinstance(ldap_url, str):
            return ldap_bind(ldap_url)

        # We have a list of servers.
        for server_url in ldap_url:
            if ldap_bind(server_url):
                return True

        return False


class OidcLoginViewResponder(LoginResponderMixin, ViewResponder):
    """ OIDC logins, using an oauth token"""

    flash_success = None
    page_title = 'Log In'
    template_name = 'keg_auth/flash-messages-only.html'

    def get(self, *args, **kwargs):
        oidc = flask.current_app.auth_manager.oidc
        oidc_check = oidc.require_login(lambda: True)()
        if oidc_check is not True:
            return oidc_check

        login_id = oidc.user_getfield("preferred_username")

        try:
            user = self.parent.verify_user(login_id=login_id)

            # User is active and password is verified
            return self.on_success(user)
        except UserNotFound:
            self.on_invalid_user(login_id)
        except UserInactive as exc:
            self.on_inactive_user(exc.user)

    def head(self, *args, **kwargs):
        return flask.abort(405, valid_methods=['GET'])

    def post(self, *args, **kwargs):
        return flask.abort(405, valid_methods=['GET'])


class OidcLogoutViewResponder(LogoutViewResponder):
    """ OIDC logout requires some extra leg-work, because token gets refreshed server-side"""

    def get(self):
        oidc = flask.current_app.auth_manager.oidc
        url_login = flask.url_for(flask.current_app.auth_manager.endpoint('login'))
        url_after_login = flask.url_for(flask.current_app.auth_manager.endpoint('after-login'))
        bad_token_redirect_resp = flask.current_app.login_manager.unauthorized()

        """ Logout won't work if user isn't authenticated to begin with, i.e. there won't be a
            token to use. Just redirect to a sane place to force a login to continue."""
        try:
            user_sub = oidc.user_getfield('sub')
        except Exception as exc:
            if 'User was not authenticated' not in str(exc):
                raise
            return flask.abort(flask.redirect(url_login))

        """ In some cases e.g. app restart, credentials store may not have valid information in the
            flask server-side info. In that case, clear the client token and refresh info from
            the oauth source. We have to have a valid id token to make logout work."""
        try:
            from oauth2client.client import OAuth2Credentials
            id_token = OAuth2Credentials.from_json(
                oidc.credentials_store[user_sub]
            ).token_response['id_token']
        except KeyError:
            oidc.logout()
            return flask.abort(bad_token_redirect_resp)

        """ Build the oauth request URI, which has to include the ID token. But, logout all client
            session info before redirecting there."""
        logout_request = '{}{}?id_token_hint={}&post_logout_redirect_uri={}'.format(
            flask.current_app.config.get('OIDC_PROVIDER_URL'),
            flask.current_app.config.get('OIDC_LOGOUT'),
            str(id_token),
            flask.current_app.config.get('OIDC_REDIRECT_BASE') + url_after_login,
        )
        oidc.logout()
        flask_login.logout_user()
        return flask.redirect(logout_request)


class OidcAuthenticator(LoginAuthenticator):
    """ Uses OIDC authentication with an oauth provider, validates against keg-auth db"""
    responder_cls = {
        'login': OidcLoginViewResponder,
        'logout': OidcLogoutViewResponder,
    }

    def __init__(self, app):
        from flask_oidc import OpenIDConnect

        oidc_settings = {
            'web': {
                'client_id': app.config.get('OIDC_CLIENT_ID'),
                'client_secret': app.config.get('OIDC_CLIENT_SECRET'),
                'auth_uri': app.config.get('OIDC_PROVIDER_URL') + '/oauth2/default/v1/authorize',
                'token_uri': app.config.get('OIDC_PROVIDER_URL') + '/oauth2/default/v1/token',
                'issuer': app.config.get('OIDC_PROVIDER_URL') + '/oauth2/default',
                'userinfo_uri': app.config.get('OIDC_PROVIDER_URL') + '/oauth2/default/userinfo',
                'redirect_uris': [
                    app.config.get('OIDC_REDIRECT_BASE') + app.config.get('OIDC_CALLBACK_ROUTE')
                ]
            }
        }

        class KAOpenIDConnect(OpenIDConnect):
            def load_secrets(self, app):
                return oidc_settings
        app.auth_manager.oidc = KAOpenIDConnect(app)

        super().__init__(app)

    def verify_user(self, login_id=None):
        user = self.user_ent.query.filter_by(username=login_id).one_or_none()

        if not user:
            raise UserNotFound
        if not user.is_active:
            raise UserInactive(user)

        return user


class JwtRequestLoader(TokenLoaderMixin, RequestLoader):
    """ Loader for JWT tokens contained in the Authorization header.

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


class TokenRequestLoader(RequestLoader):
    authentication_failure_redirect = False

    def get_authenticated_user(self):
        token = flask.request.headers.get('X-Auth-Token')

        if token is None:
            return

        user = self.user_ent.get_by_token(token)

        if user is None:
            return

        flask_login.login_user(user)
        return user
