import flask
import flask_login
import keg.web
import sqlalchemy.orm.exc as orm_exc

import kegauth.forms as forms


class AuthBaseView(keg.web.BaseView):
    def check_auth(self):
        if not flask_login.current_user.is_authenticated:
            self.handle_unauthenticated()

    def handle_unauthenticated(self):
        redirect_resp = flask.current_app.login_manager.unauthorized()
        flask.abort(redirect_resp)


class LoginBase(keg.web.BaseView):
    url = '/login'
    template_name = 'kegauth/login.html'
    form_cls = forms.LoginForm
    flash_form_error = 'The form has errors, please see below.', 'error'
    flash_success = 'Login successful.', 'success'
    flash_invalid_password = 'Invalid password.', 'error'
    flash_invalid_user = 'No user account matches: {}', 'error'
    flash_unverified_user = 'The user account "{}" has an unverified email addres.  Please check' \
        ' your email for a verification link from this website.  Or, use the "forgot' \
        ' password" link to verify the account.', 'error'
    flash_disabled_user = 'The user account "{}" has been disabled.  Please contact this' \
        ' site\'s administrators for more information.', 'error'

    def get(self):
        form = self.make_form()
        self.assign('form', form)

    def post(self):
        form = self.make_form()
        if form.validate():
            try:
                user = self.get_user(form)
                if not user.is_active:
                    self.on_inactive_user(user)
                elif not self.verify_password(user, form):
                    self.on_invalid_password()
                else:
                    # User is active and password is verified
                    return self.on_success()
            except orm_exc.NoResultFound:
                self.on_invalid_user(form)
        else:
            self.on_form_error(form)

        self.assign('form', form)

    def make_form(self):
        return self.form_cls()

    def verify_password(self, user, form):
        return user.password == form.password.data

    def get_user(self, form):
        email = form.email.data
        user_ent = flask.current_app.auth_manager.get_user_entity()
        return user_ent.query.filter_by(email=email).one()

    def on_form_error(self, form):
        flask.flash(*self.flash_form_error)

    def on_invalid_password(self):
        flask.flash(*self.flash_invalid_password)

    def on_inactive_user(self, user):
        if not user.is_verified:
            message, category = self.flash_unverified_user
            flask.flash(message.format(user.email), category)
        if not user.is_enabled:
            message, category = self.flash_disabled_user
            flask.flash(message.format(user.email), category)

    def on_invalid_user(self, form):
        message, category = self.flash_invalid_user
        email = form.email.data
        flask.flash(message.format(email), category)

    def on_success(self):
        flask.flash(*self.flash_success)
        redirect_to = flask.current_app.auth_manager.url_for('after-login')
        return flask.redirect(redirect_to)


def make_blueprint(import_name, bp_name='auth', login_cls=LoginBase):
    _blueprint = flask.Blueprint(bp_name, import_name)

    class Login(login_cls):
        blueprint = _blueprint

    return _blueprint
