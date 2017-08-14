import flask
import flask_login
from keg.db import db
import keg.web
import sqlalchemy.orm.exc as orm_exc

from kegauth import forms


class AuthBaseView(keg.web.BaseView):
    def check_auth(self):
        if not flask_login.current_user.is_authenticated:
            self.handle_unauthenticated()

    def handle_unauthenticated(self):
        redirect_resp = flask.current_app.login_manager.unauthorized()
        flask.abort(redirect_resp)


class _BaseView(keg.web.BaseView):

    def flash_and_redirect(self, flash_parts, auth_ident):
        flask.flash(*flash_parts)
        redirect_to = flask.current_app.auth_manager.url_for(auth_ident)
        flask.abort(flask.redirect(redirect_to))


class AuthFormView(_BaseView):
    flash_form_error = 'The form has errors, please see below.', 'error'
    flash_invalid_user = 'No user account matches: {}', 'error'
    flash_disabled_user = 'The user account "{}" has been disabled.  Please contact this' \
        ' site\'s administrators for more information.', 'error'

    @property
    def form_action_text(self):
        return self.page_title

    @property
    def page_heading(self):
        return self.page_title

    def get(self):
        form = self.make_form()
        self.assign_template_vars(form)

    def post(self, user=None, token=None):
        form = self.make_form()
        if form.validate():
            kwargs = {}
            if user:
                kwargs['user'] = user
            if token:
                kwargs['token'] = token
            resp = self.on_form_valid(form, **kwargs)
            if resp is not None:
                return resp
        else:
            self.on_form_error(form)

        self.assign_template_vars(form)

    def assign_template_vars(self, form):
        self.assign('form', form)
        self.assign('form_action_text', self.form_action_text)
        self.assign('page_title', self.page_title)
        self.assign('page_heading', self.page_heading)

    def make_form(self):
        return self.form_cls()

    def get_user(self, form):
        email = form.email.data
        user_ent = flask.current_app.auth_manager.get_user_entity()
        return user_ent.query.filter_by(email=email).one()

    def on_form_error(self, form):
        flask.flash(*self.flash_form_error)

    def on_invalid_user(self, form):
        message, category = self.flash_invalid_user
        email = form.email.data
        flask.flash(message.format(email), category)

    def verify_user_enabled(self, user):
        if not user.is_enabled:
            message, category = self.flash_disabled_user
            flask.flash(message.format(user.email), category)
            return False
        return True


class Login(AuthFormView):
    url = '/login'
    template_name = 'kegauth/login.html'
    form_cls = forms.Login
    page_title = 'Log In'
    flash_success = 'Login successful.', 'success'
    flash_invalid_password = 'Invalid password.', 'error'
    flash_unverified_user = 'The user account "{}" has an unverified email addres.  Please check' \
        ' your email for a verification link from this website.  Or, use the "forgot' \
        ' password" link to verify the account.', 'error'

    def on_form_valid(self, form):
        try:
            user = self.get_user(form)
            if not user.is_active:
                self.on_inactive_user(user)
            elif not self.verify_password(user, form):
                self.on_invalid_password()
            else:
                # User is active and password is verified
                return self.on_success(user)
        except orm_exc.NoResultFound:
            self.on_invalid_user(form)

    def verify_password(self, user, form):
        return user.password == form.password.data

    def on_invalid_password(self):
        flask.flash(*self.flash_invalid_password)

    def on_inactive_user(self, user):
        if not user.is_verified:
            message, category = self.flash_unverified_user
            flask.flash(message.format(user.email), category)
        self.verify_user_enabled(user)

    def on_success(self, user):
        flask_login.login_user(user)
        flask.flash(*self.flash_success)
        redirect_to = flask.current_app.auth_manager.url_for('after-login')
        return flask.redirect(redirect_to)


class ForgotPassword(AuthFormView):
    url = '/forgot-password'
    form_cls = forms.ForgotPassword
    page_title = 'Initiate Password Reset'
    template_name = 'kegauth/forgot-password.html'
    flash_success = 'Please check your email for the link to change your password.', 'success'

    def on_form_valid(self, form):
        try:
            user = self.get_user(form)
            if self.verify_user_enabled(user):
                # User is active, take action to initiate password reset
                return self.on_success(user)
        except orm_exc.NoResultFound:
            self.on_invalid_user(form)

    def on_success(self, user):
        self.send_email(user)
        flask.flash(*self.flash_success)
        redirect_to = flask.current_app.auth_manager.url_for('after-forgot')
        return flask.redirect(redirect_to)

    def send_email(self, user):
        user.token_generate()
        flask.current_app.auth_mail_manager.send_reset_password(user)


class ResetPassword(AuthFormView):
    url = '/reset-password/<int:user_id>/<token>'
    form_cls = forms.ResetPassword
    page_title = 'Complete Password Reset'
    template_name = 'kegauth/reset-password.html'
    flash_success = 'Password changed.  Please use the new password to login below.', 'success'
    flash_invalid_token = 'Password reset token was invalid or expired.  Please try again.', 'error'

    def user_loader(self, user_id):
        user_ent = flask.current_app.auth_manager.get_user_entity()
        return user_ent.query.get(user_id)

    def pre_method(self, user, token):
        if not user.token_verify(token):
            resp = self.on_invalid_token()
            # In case on_invalid_token() is replaced and it accidently fails to return a value
            # make sure we change that to a generic 400.
            flask.abort(resp or 400)

    def on_form_valid(self, form, user=None, token=None):
        assert user is not None
        assert token is not None
        return self.on_success(form, user, token)

    def on_success(self, form, user, token):
        new_password = form.password.data
        user.change_password(token, new_password)
        self.flash_and_redirect(self.flash_success, 'after-reset')

    def on_invalid_token(self):
        self.flash_and_redirect(self.flash_invalid_token, 'forgot-password')


class Logout(_BaseView):
    url = '/logout'
    flash_success = 'You have been logged out.', 'success'

    def get(self):
        flask_login.logout_user()
        self.flash_and_redirect(self.flash_success, 'after-logout')


def make_blueprint(import_name, bp_name='auth', login_cls=Login, forgot_cls=ForgotPassword,
                   reset_cls=ResetPassword, logout_cls=Logout):

    _blueprint = flask.Blueprint(bp_name, import_name)

    # It's not ideal we have to redefine the classes, but it's needed because of how
    # Keg.web.BaseView does it's meta programming.  If we don't redefine the class, then
    # the view doesn't actually get created on blueprint.
    class Login(login_cls):
        blueprint = _blueprint

    class ForgotPassword(forgot_cls):
        blueprint = _blueprint

    class ResetPassword(reset_cls):
        blueprint = _blueprint

    class Logout(logout_cls):
        blueprint = _blueprint

    return _blueprint
