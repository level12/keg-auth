from datetime import timedelta
from urllib.parse import urljoin, urlparse

import arrow
import flask
import flask_login
import sqlalchemy as sa
import string
import typing
import wtforms
from blazeutils import tolist
from keg.db import db
from sqlalchemy_utils import EmailType

from keg_auth import forms
from keg_auth.extensions import flash, lazy_gettext as _
from keg_auth.libs import get_domain_from_email
from keg_auth.model import get_username_key, get_username
from keg_auth.model.entity_registry import RegistryError

try:
    import flask_wtf
except ImportError:
    pass  # pragma: no cover

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


class AttemptBlocked(Exception):
    pass


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

    def is_domain_excluded(self, login_id):
        return False


class ViewResponder(object):
    """ View-layer logic wrapper for use in the Authenticator

        Responder should be combined with needed mixins for various functionality (forms,
        logins, etc.).

        Expected to have methods named for the request method (get, post, etc.)

        `template_name` is passed to `flask.render_template` by default
    """
    template_name = None
    _csrf_custom_handling = False

    def __init__(self, parent):
        self.template_args = {}
        self.parent = parent

    def assign(self, key, value):
        self.template_args[key] = value

    def render(self):
        return flask.render_template(self.template_name, **self.template_args)

    def handle_csrf(self):
        """ For some views that are rate-limited, we want to log all attempts, including
        those that would fail CSRF validation. Because of this, we need to circumvent
        flask-csrf's default before-request hook. The auth manager will work to exempt
        any of our auth endpoints whose class is marked with _csrf_custom_handling.

        If CSRF fails, ensure the attempt is logged, and then raise the error.

        If CSRF succeeds, the ensuing view responder methods should do any appropriate
        logging.
        """
        app = flask.current_app

        if (
            'csrf' not in app.extensions
            or not app.config['WTF_CSRF_ENABLED']
            or not app.config['WTF_CSRF_CHECK_DEFAULT']
            or flask.request.method not in app.config['WTF_CSRF_METHODS']
        ):
            return

        try:
            app.extensions['csrf'].protect()
        except flask_wtf.csrf.CSRFError:
            self.on_csrf_error()
            raise

    def on_csrf_error(self):
        pass

    def __call__(self, *args, **kwargs):
        if self._csrf_custom_handling:
            self.handle_csrf()

        method_name = flask.request.method.lower()
        method_obj = getattr(self, method_name, None)
        if not method_obj:
            raise NotImplementedError(method_name)
        resp = method_obj(*args, **kwargs)

        return resp or self.render()

    def head(self, *args, **kwargs):
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
                return  # preventing unverified users to also get the disabled alert

        if not user.is_active:
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

    def create_form(self):
        return self.form_cls()

    def assign_template_vars(self, form):
        title_var = flask.current_app.config.get('KEGAUTH_TEMPLATE_TITLE_VAR')
        self.assign('form', form)
        self.assign('form_action_text', self.page_title)
        self.assign(title_var, self.page_title)
        self.assign('page_heading', self.page_title)

    def get(self, *args, **kwargs):
        form = self.create_form()
        self.assign_template_vars(form)

    def post(self, *args, **kwargs):
        form = self.create_form()
        if form.validate():
            resp = self.on_form_valid(form)
            if resp is not None:
                return resp
        else:
            self.on_form_error(form)

        self.assign_template_vars(form)


class AttemptLimitMixin(object):
    @property
    def attempt_ent(self):
        return flask.current_app.auth_manager.entity_registry.attempt_cls

    def should_limit_attempts(self):
        if not flask.current_app.config.get('KEGAUTH_ATTEMPT_LIMIT_ENABLED'):
            # limiting can be turned off by config
            return False
        try:
            # verify the attempt entity has been configured for logging attempts
            self.attempt_ent
        except RegistryError:
            raise Exception('Rate limiting is enabled, but the attempt entity is not registered')
        return True

    def check_blocking(self, user_input, success=False):
        """Generic blocking method that will create an attempt log, and notify the calling
        method (via exception) if the attempt is blocked.

        Returns the attempt log if not blocked. If ``success`` is left False (default), The
        calling method will be responsible to set the attempt log's success flag as needed.
        """
        attempt_log = None
        if self.should_limit_attempts():
            if self.is_attempt_blocked(user_input):
                # If we are rate-limiting this attempt, we don't want to proceed with validation.
                # Validating may still allow brute forcing by measuring response time.
                attempt_log = self.log_attempt(user_input, success=False, is_during_lockout=True)
                self.on_attempt_blocked()
                raise AttemptBlocked
            else:
                attempt_log = self.log_attempt(user_input, success=success)
        return attempt_log

    @property
    def should_filter_ip(self):
        return flask.current_app.config.get('KEGAUTH_ATTEMPT_IP_LIMIT', False)

    def get_input_filters(self, username):
        input_filters = self.attempt_ent.user_input == username
        if self.should_filter_ip and self.get_request_remote_addr():
            input_filters = sa.sql.or_(
                input_filters,
                self.attempt_ent.source_ip == self.get_request_remote_addr()
            )
        return input_filters

    def get_last_limiting_attempt(self, username):
        '''
        Get the last attempt that counts toward the limit count. Attempts that count
        toward the limit before this attempt will be counted to determine if this
        attempt caused a lockout.

        For login, this will be the last failed attempt.
        For password reset, this will be the last attempt.
        '''
        raise NotImplementedError()  # pragma: no cover

    def get_limiting_attempt_count(self, before_time, username):
        '''
        Return the number of attempts that count toward the limit up to before_time.
        '''
        raise NotImplementedError  # pragma: no cover

    def is_attempt_blocked(self, username):
        last_limiting_attempt = self.get_last_limiting_attempt(username)

        if last_limiting_attempt:
            limiting_attempt_count = self.get_limiting_attempt_count(
                last_limiting_attempt.datetime_utc,
                username
            )
            # A failed attempt has caused a lockout so we should check if the lockout
            # period has passed.
            if limiting_attempt_count >= self.get_attempt_limit():
                lockout_delta = timedelta(seconds=self.get_attempt_lockout_period())
                return arrow.utcnow() - last_limiting_attempt.datetime_utc <= lockout_delta

        # We are not in a lockout period so block attempts if there are too many
        # limiting attempts in the timespan until now.
        limiting_in_timespan_count = self.get_limiting_attempt_count(arrow.utcnow(), username)
        return limiting_in_timespan_count >= self.get_attempt_limit()

    def log_attempt(self, username, *, success=True, is_during_lockout=False):
        attempt = self.attempt_ent(
            attempt_type=self.get_attempt_type(),
            user_input=username,
            success=success,
            is_during_lockout=is_during_lockout,
            datetime_utc=arrow.utcnow(),
        )
        if flask.has_request_context():
            attempt.source_ip = self.get_request_remote_addr()

        db.session.add(attempt)
        db.session.commit()
        return attempt

    def update_attempt(self, attempt, **kwargs):
        self.attempt_ent.edit(attempt.id, **kwargs)

    @staticmethod
    def get_request_remote_addr():
        return flask.request.remote_addr

    def on_attempt_blocked(self):
        flash_message = self.get_flash_attempts_limit_reached()
        if flash_message:
            flash(*flash_message)

    def get_flash_attempts_limit_reached(self):
        raise NotImplementedError  # pragma: no cover

    def get_attempt_type(self):
        raise NotImplementedError  # pragma: no cover

    def get_config_value(self, key):
        """Fetch the config value for the view specified in get_attempt_type.

        Checks the view-specific key first, and if the value is not configured,
        falls to the default for the key.

        Example: get_attempt_type returns login, and key is attempt_limit.
        - Checks for KEGAUTH_LOGIN_ATTEMPT_LIMIT first
        - If that is not set, falls back to KEGAUTH_ATTEMPT_LIMIT
        """
        view_key = self.get_attempt_type().upper()
        key = key.upper()
        return flask.current_app.config.get(
            f'KEGAUTH_{view_key}_{key}',
            flask.current_app.config.get(f'KEGAUTH_{key}')
        )

    def get_attempt_limit(self):
        return self.get_config_value('attempt_limit')

    def get_attempt_timespan(self):
        return self.get_config_value('attempt_timespan')

    def get_attempt_lockout_period(self):
        return self.get_config_value('attempt_lockout')


class PasswordSetterResponderBase(FormResponderMixin, ViewResponder):
    """ Base logic for resetting passwords and verifying accounts via token"""
    form_cls = forms.SetPassword
    template_name = 'keg-auth/set-password.html'
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

    def create_form(self):
        return self.form_cls(user=self.user)

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


class ResetPasswordViewResponder(AttemptLimitMixin, PasswordSetterResponderBase):
    """ Responder for resetting passwords via token on keg-auth logins"""
    url = '/reset-password/<int:user_id>/<token>'
    page_title = _('Complete Password Reset')
    submit_button_text = _('Change Password')
    flash_success = _('Password changed.  Please use the new password to login below.'), 'success'
    on_success_endpoint = 'after-reset'

    def on_form_valid(self, form):
        try:
            self.check_blocking(get_username(self.user), success=True)
        except AttemptBlocked:
            # If we are rate-limiting this attempt, we don't want to proceed with validation.
            # Validating may still allow brute forcing by measuring response time.
            return

        new_password = form.password.data
        self.user.change_password(self.token, new_password)
        self.flash_and_redirect(self.flash_success, self.on_success_endpoint)

    def get_flash_attempts_limit_reached(self):
        return _('Too many password reset attempts.'), 'error'

    def get_attempt_type(self):
        return 'reset'

    def get_last_limiting_attempt(self, username):
        return self.attempt_ent.query.filter_by(
            is_during_lockout=False,
            attempt_type=self.get_attempt_type(),
        ).filter(
            self.get_input_filters(username)
        ).order_by(
            self.attempt_ent.datetime_utc.desc(),
        ).first()

    def get_limiting_attempt_count(self, before_time, username):
        timespan_start = before_time + timedelta(seconds=-self.get_attempt_timespan())
        return self.attempt_ent.query.filter(
            self.get_input_filters(username),
            self.attempt_ent.is_during_lockout == sa.false(),
            self.attempt_ent.datetime_utc > timespan_start,
            self.attempt_ent.datetime_utc <= before_time,
            self.attempt_ent.attempt_type == self.get_attempt_type(),
        ).count()


class VerifyAccountViewResponder(PasswordSetterResponderBase):
    """ Responder for verifying users via email token for keg-auth logins"""
    url = '/verify-account/<int:user_id>/<token>'
    page_title = _('Verify Account & Set Password')
    submit_button_text = _('Verify & Set Password')
    flash_success = _('Account verified & password set.  Please use the new password to login'
                      ' below.'), 'success'
    on_success_endpoint = 'after-verify-account'


class PasswordFormViewResponder(AttemptLimitMixin, LoginResponderMixin,
                                FormResponderMixin, ViewResponder):
    """ Master responder for username/password-style logins, using a login form"""
    template_name = 'keg-auth/login.html'
    page_title = _('Log In')
    flash_invalid_password = _('Invalid password.'), 'error'
    _csrf_custom_handling = True

    @property
    def form_cls(self):
        return forms.login_form()

    def on_form_error(self, form):
        super().on_form_error(form)
        username = form.login_id.data
        try:
            # ensure we log this even though the form didn't validate
            self.check_blocking(username)
        except AttemptBlocked:
            pass

    def on_csrf_error(self):
        username = flask.request.form.get('login_id', '')
        try:
            # ensure we log this even though the form didn't validate
            self.check_blocking(username)
        except AttemptBlocked:
            pass

    def on_form_valid(self, form):
        username = form.login_id.data
        try:
            attempt = self.check_blocking(username)
        except AttemptBlocked:
            # If we are rate-limiting this attempt, we don't want to proceed with validation.
            # Validating may still allow brute forcing by measuring response time. Skipping it
            # may help mitigate DoS attacks on the login page as password hashing is typically
            # an expensive operation
            return

        try:
            # We want to know if the login attempt was successful so we'll try
            # to verify the user. If the user is verified but the attempt is blocked,
            # mark the attempt as successful and abort.
            user = self.parent.verify_user(
                login_id=form.login_id.data,
                password=form.password.data
            )

            if attempt:
                self.update_attempt(attempt, success=True)

            # User is active and password is verified
            return self.on_success(user)
        except UserNotFound:
            self.on_invalid_user(form.login_id.data)
        except UserInactive as exc:
            self.on_inactive_user(exc.user)
        except UserInvalidAuth as exc:
            self.on_invalid_password(exc.user)

    def on_invalid_password(self, user):
        if self.flash_invalid_password:
            flash(*self.flash_invalid_password)

    def get_flash_attempts_limit_reached(self):
        return _('Too many failed login attempts.'), 'error'

    def get_attempt_type(self):
        return 'login'

    def get_last_limiting_attempt(self, username):
        return self.attempt_ent.query.filter_by(
            success=False,
            is_during_lockout=False,
            attempt_type=self.get_attempt_type(),
        ).filter(
            self.get_input_filters(username)
        ).order_by(
            self.attempt_ent.datetime_utc.desc(),
        ).first()

    def get_limiting_attempt_count(self, before_time, username):
        last_successful_attempt = self.attempt_ent.query.filter_by(
            success=True,
            is_during_lockout=False,
            attempt_type=self.get_attempt_type()
        ).filter(
            self.get_input_filters(username)
        ).order_by(
            self.attempt_ent.datetime_utc.desc(),
        ).first()

        def is_within_timespan(attempt):
            timespan_start = before_time + timedelta(seconds=-self.get_attempt_timespan())
            return attempt.datetime_utc > timespan_start

        if last_successful_attempt and is_within_timespan(last_successful_attempt):
            timespan_start = last_successful_attempt.datetime_utc
        else:
            timespan_start = before_time + timedelta(seconds=-self.get_attempt_timespan())

        return self.attempt_ent.query.filter(
            self.get_input_filters(username),
            self.attempt_ent.success == sa.false(),
            self.attempt_ent.is_during_lockout == sa.false(),
            self.attempt_ent.datetime_utc > timespan_start,
            self.attempt_ent.datetime_utc <= before_time,
            self.attempt_ent.attempt_type == self.get_attempt_type(),
        ).count()


class OAuthLoginViewResponder(ViewResponder):
    """ OAuth logins, using a provider via authlib"""
    url = '/login/<name>'

    def get(self, *args, **kwargs):
        name = kwargs.get('name')
        oauth = flask.current_app.auth_manager.oauth
        client = oauth.create_client(name)
        if not client:
            return flask.abort(404)

        redirect_uri = flask.current_app.auth_manager.url_for(
            'oauth-authorize', name=name, _external=True
        )
        return client.authorize_redirect(redirect_uri)

    def head(self, *args, **kwargs):
        return flask.abort(405, valid_methods=['GET'])

    def post(self, *args, **kwargs):
        return flask.abort(405, valid_methods=['GET'])


class OAuthAuthorizeViewResponder(LoginResponderMixin, ViewResponder):
    """ OAuth logins, using a provider via authlib"""
    url = '/oauth-authorize/<name>'
    template_name = 'keg-auth/flash-messages-only.html'

    def get(self, *args, **kwargs):
        name = kwargs.get('name')
        oauth = flask.current_app.auth_manager.oauth
        client = oauth.create_client(name)
        if not client:
            return flask.abort(404)

        oauth_profile = self.parent.select_oauth_profile(name)
        token = client.authorize_access_token()
        userinfo = token.get('userinfo')
        if not userinfo:
            userinfo = client.userinfo()

        login_id = userinfo.get(oauth_profile['id_field'])

        try:
            user = self.parent.verify_user(profile_name=name, login_id=login_id)

            # User is active and password is verified
            return self.on_success(user)
        except UserNotFound:
            self.on_invalid_user(login_id)
        except UserInactive as exc:
            self.on_inactive_user(exc.user)

    def head(self, *args, **kwargs):
        return flask.abort(405, valid_methods=['GET'])


class ForgotPasswordViewResponder(AttemptLimitMixin, UserResponderMixin, FormResponderMixin,
                                  ViewResponder):
    """ Master responder for keg-integrated logins, using an email form"""
    url = '/forgot-password'
    form_cls = forms.ForgotPassword
    page_title = _('Initiate Password Reset')
    template_name = 'keg-auth/forgot-password.html'
    flash_success = _('Please check your email for the link to change your password.'), 'success'
    _csrf_custom_handling = True

    def __call__(self, *args, **kwargs):
        if not flask.current_app.auth_manager.mail_manager:
            flask.abort(404)

        return super(ForgotPasswordViewResponder, self).__call__(*args, **kwargs)

    def on_csrf_error(self):
        try:
            # ensure we log this even though the form didn't validate
            self.check_blocking(flask.request.form.get('email', ''))
        except AttemptBlocked:
            pass

    def on_form_error(self, form):
        super().on_form_error(form)
        try:
            # ensure we log this even though the form didn't validate
            self.check_blocking(form.email.data)
        except AttemptBlocked:
            pass

    def on_form_valid(self, form):
        try:
            attempt = self.check_blocking(form.email.data)
        except AttemptBlocked:
            # If we are rate-limiting this attempt, we don't want to proceed with validation.
            # Validating may still allow brute forcing by measuring response time.
            return

        try:
            user = self.parent.verify_user(login_id=form.email.data, allow_unverified=True)

            if attempt:
                self.update_attempt(attempt, success=True)

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

    def get_flash_attempts_limit_reached(self):
        return _('Too many failed attempts.'), 'error'

    def get_attempt_type(self):
        return 'forgot'

    def get_last_limiting_attempt(self, username):
        return self.attempt_ent.query.filter_by(
            success=False,
            is_during_lockout=False,
            attempt_type=self.get_attempt_type(),
        ).filter(
            self.get_input_filters(username)
        ).order_by(
            self.attempt_ent.datetime_utc.desc(),
        ).first()

    def get_limiting_attempt_count(self, before_time, username):
        last_successful_attempt = self.attempt_ent.query.filter_by(
            success=True,
            is_during_lockout=False,
            attempt_type=self.get_attempt_type()
        ).filter(
            self.get_input_filters(username)
        ).order_by(
            self.attempt_ent.datetime_utc.desc(),
        ).first()

        def is_within_timespan(attempt):
            timespan_start = before_time + timedelta(seconds=-self.get_attempt_timespan())
            return attempt.datetime_utc > timespan_start

        if last_successful_attempt and is_within_timespan(last_successful_attempt):
            timespan_start = last_successful_attempt.datetime_utc
        else:
            timespan_start = before_time + timedelta(seconds=-self.get_attempt_timespan())

        return self.attempt_ent.query.filter(
            self.get_input_filters(username),
            self.attempt_ent.success == sa.false(),
            self.attempt_ent.is_during_lockout == sa.false(),
            self.attempt_ent.datetime_utc > timespan_start,
            self.attempt_ent.datetime_utc <= before_time,
            self.attempt_ent.attempt_type == self.get_attempt_type(),
        ).count()


class LogoutViewResponder(ViewResponder):
    url = '/logout'
    flash_success = _('You have been logged out.'), 'success'

    def get(self):
        flask_login.logout_user()
        if self.flash_success:
            flash(*self.flash_success)
        redirect_to = flask.current_app.auth_manager.url_for('after-logout')
        flask.abort(flask.redirect(redirect_to))


def not_found_view_responder_factory(target_url):
    class NotFoundViewResponder(ViewResponder):
        url = target_url

        def get(self):
            flask.abort(404)

    return NotFoundViewResponder


class RedirectLoginViewResponder(ViewResponder):
    url = '/login'

    def get(self):
        target = flask.current_app.config.get('KEGAUTH_REDIRECT_LOGIN_TARGET')
        if not target or not target.startswith('/'):
            raise Exception('KEGAUTH_REDIRECT_LOGIN_TARGET not set or not relative')
        return flask.redirect(target)


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


class RedirectAuthenticator(LoginAuthenticator):
    """ Redirects to another source for authentication. Useful for when we have an OAuth source
        in mind for primary auth. We will want to redirect /login there, keep /logout, and
        direct other responder keys to return 404.

        Use KEGAUTH_REDIRECT_LOGIN_TARGET to set the login target."""
    responder_cls = {
        'login': RedirectLoginViewResponder,
        'forgot-password': not_found_view_responder_factory('/forgot-password'),
        'reset-password': not_found_view_responder_factory('/reset-password'),
        'verify-account': not_found_view_responder_factory('/verify-account'),
        'logout': LogoutViewResponder,
    }


class KegAuthenticator(PasswordAuthenticatorMixin, LoginAuthenticator):
    """ Uses username/password authentication with a login form, validates against keg-auth db"""
    responder_cls = {
        'login': PasswordFormViewResponder,
        'forgot-password': ForgotPasswordViewResponder,
        'reset-password': ResetPasswordViewResponder,
        'verify-account': VerifyAccountViewResponder,
        'logout': LogoutViewResponder,
    }

    def __init__(self, app):
        super().__init__(app)

        self.load_domain_exclusions(app)

    def load_domain_exclusions(self, app):
        domain_exclusions = []
        for profile in app.config.get('KEGAUTH_OAUTH_PROFILES', []):
            domain_exclusions.extend(tolist(profile.get('domain_filter', [])))
        self.domain_exclusions = domain_exclusions

    def is_domain_excluded(self, login_id):
        """Domains configured for OAuth access are excluded from the password authenticator.

        Any operations not using ``verify_user`` should check for exclusion."""
        if self.domain_exclusions:
            domain = get_domain_from_email(login_id)
            if domain and domain in self.domain_exclusions:
                return True
        return False

    def verify_user(self, login_id=None, password=None, allow_unverified=False):
        if self.is_domain_excluded(login_id):
            # apply a domain filter before looking up the user record
            raise UserNotFound

        user = self.user_ent.query.filter(
            sa.func.lower(self.user_ent.username) == (login_id.lower() if login_id else None)
        ).one_or_none()

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


class OAuthAuthenticator(LoginAuthenticator):
    """ Uses OAuth authentication via authlib, validates user info against keg-auth db"""
    responder_cls = {
        'login': OAuthLoginViewResponder,
        'authorize': OAuthAuthorizeViewResponder,
    }

    def __init__(self, app):
        self.load_profiles(app)
        super().__init__(app)

    def load_profiles(self, app):
        from authlib.integrations.flask_client import OAuth

        app.auth_manager.oauth = oauth = OAuth(app)
        for profile in app.config.get('KEGAUTH_OAUTH_PROFILES'):
            expected_keys = 'domain_filter', 'id_field', 'oauth_client_kwargs'
            if len(set(expected_keys) & set(profile.keys())) != len(expected_keys):
                expected_keys_display = ', '.join(expected_keys)
                raise Exception(
                    f'OAuth profile is missing keys, expects {expected_keys_display}'
                )
            oauth.register(**profile['oauth_client_kwargs'])

    def select_oauth_profile(self, name):
        return next(
            filter(
                lambda profile: profile['oauth_client_kwargs']['name'] == name,
                flask.current_app.config.get('KEGAUTH_OAUTH_PROFILES', [])
            ), None
        )

    def verify_user(self, profile_name=None, login_id=None):
        oauth_profile = self.select_oauth_profile(profile_name)
        if not oauth_profile:
            raise Exception(f'OAuth profile {profile_name} is not configured')

        # Some OAuth providers, like Google, can be configured to only pass through users
        #   from specific domains. But we shouldn't make that assumption for all providers,
        #   and since we have the domain filter also for disallowing logins in KegAuthenticator,
        #   it's best to check it here as well.
        if oauth_profile.get('domain_filter'):
            domain = get_domain_from_email(login_id)
            if domain and domain not in tolist(oauth_profile['domain_filter']):
                raise UserNotFound

        user = self.user_ent.query.filter_by(username=login_id).one_or_none()

        if not user:
            raise UserNotFound

        # Users from domains filtered to OAuth do not follow the usual verification
        #   process. Check for that here - if OAuth source says it's a verified user,
        #   trust it.
        if not user.is_verified:
            user.is_verified = True
            db.session.commit()

        if not user.is_active:
            raise UserInactive(user)

        return user


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
        Check the given username/password combination at the application's configured LDAP server.
        Returns `True` if the user authentication is successful, `False` otherwise. NOTE: By
        request, authentication can be bypassed by setting the KEGAUTH_LDAP_TEST_MODE configuration
        setting to `True`. When set, all authentication attempts will succeed!
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
            This method is the complement of `user_lookup_loader`
            """
            return user.session_key

        @jwt_manager.user_lookup_loader
        def user_loader_callback_loader(jwt_header, jwt_data):
            """
            Load a user entity from the JWT token
            This method is the complement of `user_identity_loader`

            Note, if user is not found or inactive, fail silently - user just won't get loaded
            """
            data_key = flask.current_app.config.get('JWT_IDENTITY_CLAIM')
            return self.user_ent.get_by(session_key=jwt_data[data_key], is_active=True)

    @staticmethod
    def get_authenticated_user():
        try:
            if flask_jwt_extended.verify_jwt_in_request() is None:
                return None
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


class PasswordCharset(typing.NamedTuple):
    name: str
    alphabet: str


class PasswordPolicyError(Exception):
    pass


PasswordCheckFunction = typing.Callable[[str, typing.Any], None]


class PasswordPolicy:
    """
    A base class that defines password requirements for the application.
    This class defines some basic, common validations and can be extended or limited by subclassing.

    To define additional password checks, create a method on your subclass that accepts a
    password string and a user entity object and raises PasswordPolicyError if the password does
    not meet the requirement you intend to check. Then override password_checks to add your method
    to the returned list of methods.

    To remove a password check that is enabled by default, override password_checks and return only
    the methods you wish to use.

    Default settings are based on NIST guidelines and some common restrictions.
    """

    """
    Minimum password length for check_length validation
    """
    min_length: int = 8

    """
    Character sets used for checking minimum "complexity" in check_character_set validation
    """
    required_char_types: typing.List[PasswordCharset] = [
        PasswordCharset(_('lowercase letter'), string.ascii_lowercase),
        PasswordCharset(_('uppercase letter'), string.ascii_uppercase),
        PasswordCharset(_('number'), string.digits),
        PasswordCharset(_('symbol'), ''.join(sorted(
            set(string.printable)
            - set(string.whitespace + string.ascii_letters + string.digits))
        )),
    ]

    """
    Minimum character number of different character types required in check_character_set validation
    """
    required_min_char_types: int = 3

    def check_length(self, pw: str, user):
        """
        Raises PasswordPolicyError if a password is not at least min_length characters long.
        :param pw: password to check
        :param user: user entity
        """
        if len(pw) < self.min_length:
            raise PasswordPolicyError(_(
                'Password must be at least {min_length} characters long',
                min_length=self.min_length
            ))

    def check_character_set(self, pw: str, user):
        """
        Raises PasswordPolicyError if a password does not contain at least one character from
        at least `required_at_least_char_types` of the alphabets in `required_char_sets`.
        :param pw: password to check
        :param user: user entity
        """

        missing = []
        for name, alphabet in self.required_char_types:
            if not set(pw) & set(alphabet):
                missing.append(name)

        if len(missing) > len(self.required_char_types) - self.required_min_char_types:
            if len(self.required_char_types) == 1:
                message = _('Password must include a {type}', type=self.required_char_types[0].name)
            else:
                first_part = ', '.join(str(t.name) for t in self.required_char_types[:-1])
                message = _(
                    'Password must include at least {required} of {first} and/or {last}',
                    required=self.required_min_char_types,
                    first=first_part,
                    last=self.required_char_types[-1].name
                )

            raise PasswordPolicyError(message)

    def check_does_not_contain_username(self, pw: str, user):
        """
        Raises PasswordPolicyError if the password contains the username. This is case insensitive.
        :param pw: password to check
        :param user: user entity
        """
        user_cls = user.__class__
        username_key = get_username_key(user_cls)
        username = getattr(user, username_key)
        username_col = getattr(user_cls, username_key)
        if isinstance(username_col.type, EmailType):
            username = user.username.split('@')[0]

        if username.casefold() in pw.casefold():
            raise PasswordPolicyError(_('Password may not contain username'))

    def password_checks(self) -> typing.List[PasswordCheckFunction]:
        return [
            self.check_length,
            self.check_character_set,
            self.check_does_not_contain_username,
        ]

    @classmethod
    def generate_validator(cls, check: PasswordCheckFunction) -> typing.Callable:
        def validator(form: wtforms.Form, field: wtforms.Field):
            try:
                check(field.data, form.user)
            except PasswordPolicyError as e:
                raise wtforms.ValidationError(str(e))
        return validator

    @classmethod
    def form_validators(cls):
        policy = cls()
        return [cls.generate_validator(c) for c in policy.password_checks()]


class DefaultPasswordPolicy(PasswordPolicy):
    """
    A bare-bones, very permissive policy to use as a default if none is set on initialization.
    """
    def password_checks(self):
        return [self.check_length]
