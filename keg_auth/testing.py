# Using unicode_literals instead of adding 'u' prefix to all stings that go to SA.
from __future__ import unicode_literals

from blazeutils import tolist
from blazeutils.containers import LazyDict
import flask
import flask_webtest
import sqlalchemy as sa
import wrapt

from keg_auth.model import entity_registry


class AuthTests(object):
    """
        These tests are designed so they can can be imported into an application's tests
        and ran to ensure customization of KegAuth hasn't broken basic functionality.

        TODO: the messages we test for need to be configurable on the class in case the app
        customizes then.  Ditto some of the redirect logic.
    """
    login_url = '/login'
    protected_url = '/secret1'
    forgot_password_url = '/forgot-password'
    reset_password_url = '/reset-password'
    logout_url = '/logout'
    after_logout_url = '/login'

    def setup(self):
        self.user_ent.delete_cascaded()

    def test_login_get(self):
        app = flask.current_app
        client = flask_webtest.TestApp(app)
        resp = client.get(self.login_url)
        assert resp.status_code == 200

    def test_login_form_error(self):
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(self.login_url)

        resp.form['email'] = 'foo'
        resp = resp.form.submit(status=200)

        assert resp.flashes == [('error', 'The form has errors, please see below.')]

    def test_login_field_success(self):
        self.user_ent.testing_create(email='foo@bar.com', password='pass')

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(self.login_url)

        resp.form['email'] = 'foo@bar.com'
        resp.form['password'] = 'pass'
        resp = resp.form.submit()

        assert resp.status_code == 302, resp.html
        assert resp.headers['Location'] == 'http://keg.example.com/'
        assert resp.flashes == [('success', 'Login successful.')]

    def test_login_invalid_password(self):
        self.user_ent.testing_create(email='foo@bar.com', password='pass')

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(self.login_url)

        resp.form['email'] = 'foo@bar.com'
        resp.form['password'] = 'badpass'
        resp = resp.form.submit(status=200)

        assert resp.flashes == [('error', 'Invalid password.')]

    def test_login_user_missing(self):
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(self.login_url)

        resp.form['email'] = 'foo@bar.com'
        resp.form['password'] = 'badpass'
        resp = resp.form.submit(status=200)

        assert resp.flashes == [('error', 'No user account matches: foo@bar.com')]

    def test_login_user_unverified(self):
        self.user_ent.testing_create(email='foo@bar.com', password='pass', is_verified=False)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(self.login_url)

        resp.form['email'] = 'foo@bar.com'
        resp.form['password'] = 'badpass'
        resp = resp.form.submit(status=200)

        msg = 'The user account "foo@bar.com" has an unverified email addres.  Please check' \
            ' your email for a verification link from this website.  Or, use the "forgot' \
            ' password" link to verify the account.'
        assert resp.flashes == [('error', msg)]

    def test_login_user_disabled(self):
        self.user_ent.testing_create(email='foo@bar.com', password='pass', is_enabled=False)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(self.login_url)

        resp.form['email'] = 'foo@bar.com'
        resp.form['password'] = 'badpass'
        resp = resp.form.submit(status=200)

        msg = 'The user account "foo@bar.com" has been disabled.  Please contact this site\'s' \
            ' administrators for more information.'

        assert resp.flashes == [('error', msg)]

    def test_login_protection(self):
        self.user_ent.testing_create(email='foo@bar.com', password='pass')

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(self.protected_url, status=302)
        full_login_url = 'http://keg.example.com{}'.format(self.login_url)
        assert resp.headers['Location'].startswith(full_login_url)

        resp = resp.follow()
        resp.form['email'] = 'foo@bar.com'
        resp.form['password'] = 'pass'
        resp = resp.form.submit(status=302)
        assert resp.flashes == [('success', 'Login successful.')]

        # Now that we have logged in, we should be able to get to the page.
        client.get(self.protected_url, status=200)

    def test_forgot_pw_form_error(self):
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(self.forgot_password_url)
        resp = resp.form.submit(status=200)

        assert resp.flashes == [('error', 'The form has errors, please see below.')]

    def test_forgot_pw_invalid_user(self):
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(self.forgot_password_url)

        resp.form['email'] = 'foo@bar.com'
        resp = resp.form.submit(status=200)

        assert resp.flashes == [('error', 'No user account matches: foo@bar.com')]

    def test_forgot_pw_user_disabled(self):
        self.user_ent.testing_create(email='foo@bar.com', password='pass', is_enabled=False)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(self.forgot_password_url)

        resp.form['email'] = 'foo@bar.com'
        resp = resp.form.submit(status=200)

        msg = 'The user account "foo@bar.com" has been disabled.  Please contact this site\'s' \
            ' administrators for more information.'

        assert resp.flashes == [('error', msg)]

    def test_forgot_pw_success(self):
        self.user_ent.testing_create(email='foo@bar.com')

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(self.forgot_password_url)

        resp.form['email'] = 'foo@bar.com'
        resp = resp.form.submit(status=302)

        msg = 'Please check your email for the link to change your password.'

        assert resp.flashes == [('success', msg)]

        full_login_url = 'http://keg.example.com{}'.format(self.login_url)
        assert resp.headers['Location'] == full_login_url

    def test_reset_pw_success(self):
        user = self.user_ent.testing_create()
        token = user.token_generate()
        url = '/{}/{}/{}'.format(self.reset_password_url, user.id, token)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url, status=200)

        resp.form['password'] = 'foo'
        resp.form['confirm'] = 'foo'
        resp = resp.form.submit(status=302)

        msg = 'Password changed.  Please use the new password to login below.'
        assert resp.flashes == [('success', msg)]

        full_login_url = 'http://keg.example.com{}'.format(self.login_url)
        assert resp.headers['Location'] == full_login_url

    def test_reset_pw_form_error(self):
        user = self.user_ent.testing_create()
        token = user.token_generate()
        url = '{}/{}/{}'.format(self.reset_password_url, user.id, token)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url, status=200)
        resp = resp.form.submit(status=200)

        assert resp.flashes == [('error', 'The form has errors, please see below.')]

    def test_reset_pw_missing_user(self):
        url = '{}/99999999/123'.format(self.reset_password_url)

        client = flask_webtest.TestApp(flask.current_app)
        client.get(url, status=404)

    def test_reset_pw_bad_token(self):
        user = self.user_ent.testing_create()
        url = '{}/{}/abc'.format(self.reset_password_url, user.id)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url, status=302)

        msg = 'Authentication token was invalid or expired.  Please fill out the form below to' \
            ' get a new token.'
        assert resp.flashes == [('error', msg)]

        full_login_url = 'http://keg.example.com{}'.format(self.forgot_password_url)
        assert resp.headers['Location'] == full_login_url

    def test_verify_account_success(self):
        user = self.user_ent.testing_create(is_verified=False)
        assert not user.is_verified

        user.token_generate()
        url = flask.current_app.auth_manager.verify_account_url(user)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url, status=200)

        resp.form['password'] = 'foo'
        resp.form['confirm'] = 'foo'
        resp = resp.form.submit(status=302)

        msg = 'Account verified & password set.  Please use the new password to login below.'
        assert resp.flashes == [('success', msg)]

        full_login_url = 'http://keg.example.com{}'.format(self.login_url)
        assert resp.headers['Location'] == full_login_url

        assert user.is_verified

    def test_verify_account_form_error(self):
        user = self.user_ent.testing_create()
        user.token_generate()
        url = flask.current_app.auth_manager.verify_account_url(user)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url, status=200)
        resp = resp.form.submit(status=200)

        assert resp.flashes == [('error', 'The form has errors, please see below.')]

    def test_verify_account_missing_user(self):
        user = LazyDict(id=9999999, _token_plain='123')
        url = flask.current_app.auth_manager.verify_account_url(user)

        client = flask_webtest.TestApp(flask.current_app)
        client.get(url, status=404)

    def test_verify_account_bad_token(self):
        user = self.user_ent.testing_create()
        user._token_plain = 'abc'
        url = flask.current_app.auth_manager.verify_account_url(user)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url, status=302)

        msg = 'Authentication token was invalid or expired.  Please fill out the form below to' \
            ' get a new token.'
        assert resp.flashes == [('error', msg)]

        full_login_url = 'http://keg.example.com{}'.format(self.forgot_password_url)
        assert resp.headers['Location'] == full_login_url

    def test_logout(self):
        user = self.user_ent.testing_create()
        client = flask_webtest.TestApp(flask.current_app)
        with client.session_transaction() as sess:
            sess['user_id'] = user.id

        # Make sure our client is actually logged in
        client.get(self.protected_url, status=200)

        # logout
        resp = client.get(self.logout_url, status=302)
        assert resp.flashes == [('success', 'You have been logged out.')]

        # Check redirect location
        full_login_url = 'http://keg.example.com{}'.format(self.after_logout_url)
        assert resp.headers['Location'] == full_login_url

        # Confirm logout occured
        client.get(self.protected_url, status=302)


@wrapt.decorator
def user_request(wrapped, instance, args, kwargs):
    new_kwargs = kwargs.copy()
    user = new_kwargs.pop('user', None)
    extra_environ = new_kwargs.setdefault('extra_environ', {})
    if user is not None:
        extra_environ['TEST_USER_ID'] = str(user.id)
    return wrapped(*args, **new_kwargs)


class AuthTestApp(flask_webtest.TestApp):
    def __init__(self, app, **kwargs):
        user = kwargs.pop('user', None)
        extra_environ = kwargs.pop('extra_environ', {})
        if user is not None:
            extra_environ['TEST_USER_ID'] = str(user.id)
        super(AuthTestApp, self).__init__(app, extra_environ=extra_environ, **kwargs)

    @user_request
    def get(self, *args, **kwargs):
        return super(AuthTestApp, self).get(*args, **kwargs)

    @user_request
    def post(self, *args, **kwargs):
        return super(AuthTestApp, self).post(*args, **kwargs)

    @user_request
    def put(self, *args, **kwargs):
        return super(AuthTestApp, self).put(*args, **kwargs)

    @user_request
    def patch(self, *args, **kwargs):
        return super(AuthTestApp, self).patch(*args, **kwargs)

    @user_request
    def delete(self, *args, **kwargs):
        return super(AuthTestApp, self).delete(*args, **kwargs)

    @user_request
    def options(self, *args, **kwargs):
        return super(AuthTestApp, self).options(*args, **kwargs)

    @user_request
    def head(self, *args, **kwargs):
        return super(AuthTestApp, self).head(*args, **kwargs)

    @user_request
    def post_json(self, *args, **kwargs):
        return super(AuthTestApp, self).post_json(*args, **kwargs)

    @user_request
    def put_json(self, *args, **kwargs):
        return super(AuthTestApp, self).put_json(*args, **kwargs)

    @user_request
    def patch_json(self, *args, **kwargs):
        return super(AuthTestApp, self).patch_json(*args, **kwargs)

    @user_request
    def delete_json(self, *args, **kwargs):
        return super(AuthTestApp, self).delete_json(*args, **kwargs)


def login_client_with_permissions(*permissions):
    """ Get an AuthTestApp instance and a User instance having the specified permissions

        Usage: permissions can be scalar or list, giving either tokens or Permission instances
        Returns: (AuthTestApp, User) tuple
    """
    perm_cls = entity_registry.registry.permission_cls
    perm_ents = [
        perm_cls.get_by_token(perm)
        if not isinstance(perm, perm_cls) else perm
        for perm in tolist(permissions)
    ]
    current_user = entity_registry.registry.user_cls.testing_create(permissions=perm_ents)
    client = AuthTestApp(flask.current_app, user=current_user)
    return client, current_user


class ViewTestBase:
    """ Simple helper class that will set up Permission tokens as specified, log in a user, and
        provide the test app client on the class for use in tests.

        Usage: `permissions` class attribute can be scalar or list, giving either tokens or
        Permission instances

        Tests:
        - `self.current_user`: User instance that is logged in
        - `self.client`: AuthTestApp instance
    """
    permissions = tuple()

    @classmethod
    def setup_class(cls):
        cls.user_ent = entity_registry.registry.user_cls
        cls.permission_ent = entity_registry.registry.permission_cls
        cls.user_ent.delete_cascaded()

        # ensure all of the tokens exists
        for perm in tolist(cls.permissions):
            if not isinstance(perm, cls.permission_ent):
                try:
                    cls.permission_ent.testing_create(token=perm)
                except sa.exc.IntegrityError:
                    pass

        cls.client, cls.current_user = login_client_with_permissions(*tolist(cls.permissions))
