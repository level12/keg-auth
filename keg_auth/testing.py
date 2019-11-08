# Using unicode_literals instead of adding 'u' prefix to all stings that go to SA.
from __future__ import unicode_literals

try:
    from unittest import mock
except ImportError:
    import mock
from urllib.parse import urlparse

from blazeutils import tolist
from blazeutils.containers import LazyDict
from six.moves import urllib
import flask
import flask_webtest
import passlib
import wrapt


class AuthTests(object):
    """
        These tests are designed so they can can be imported into an application's tests
        and ran to ensure customization of KegAuth hasn't broken basic functionality.
    """
    protected_url = '/secret1'
    protected_url_permissions = None

    def setup(self):
        self.user_ent.delete_cascaded()

    def test_login_get(self):
        app = flask.current_app
        client = flask_webtest.TestApp(app)
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('login')))
        assert resp.status_code == 200

    def test_login_form_error(self):
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('login')))

        resp.form['login_id'] = 'foo'
        resp = resp.form.submit(status=200)

        flash_form_error = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['login'].flash_form_error
        category = flash_form_error[1]
        message = flash_form_error[0]
        assert resp.flashes == [(category, message)]

    def test_login_field_success(self):
        self.user_ent.testing_create(email='foo@bar.com', password='pass')

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('login')))

        resp.form['login_id'] = 'foo@bar.com'
        resp.form['password'] = 'pass'
        resp = resp.form.submit()

        assert resp.status_code == 302, resp.html
        assert resp.headers['Location'] == flask.url_for(
            flask.current_app.auth_manager.endpoint('after-login')
        )
        flash_success = flask.current_app.auth_manager.login_authenticator_cls.responder_cls['login'].flash_success  # noqa
        category = flash_success[1]
        message = flash_success[0]
        assert resp.flashes == [(category, message)]

    def test_login_field_success_next_parameter(self):
        self.user_ent.testing_create(email='foo@bar.com', password='pass')

        next = '/foo'
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('{}?next={}'.format(
            flask.url_for(flask.current_app.auth_manager.endpoint('login')), next)
        )

        resp.form['login_id'] = 'foo@bar.com'
        resp.form['password'] = 'pass'
        resp = resp.form.submit()

        assert resp.status_code == 302, resp.html
        assert resp.headers['Location'] == 'http://keg.example.com{}'.format(next)
        flash_success = flask.current_app.auth_manager.login_authenticator_cls.responder_cls['login'].flash_success  # noqa
        category = flash_success[1]
        message = flash_success[0]
        assert resp.flashes == [(category, message)]

    def test_login_field_success_next_session(self):
        self.user_ent.testing_create(email='foo@bar.com', password='pass')

        next = '/foo'
        with mock.patch.dict(flask.current_app.config, {'USE_SESSION_FOR_NEXT': True}):
            client = flask_webtest.TestApp(flask.current_app)
            with client.session_transaction() as sess:
                sess['next'] = next
            resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('login')))

            resp.form['login_id'] = 'foo@bar.com'
            resp.form['password'] = 'pass'
            resp = resp.form.submit()

        assert resp.status_code == 302, resp.html
        assert resp.headers['Location'] == 'http://keg.example.com{}'.format(next)
        flash_success = flask.current_app.auth_manager.login_authenticator_cls.responder_cls['login'].flash_success  # noqa
        category = flash_success[1]
        message = flash_success[0]
        assert resp.flashes == [(category, message)]

    def test_next_parameter_not_open_redirect(self):
        """ensure following the "next" parameter doesn't allow for an open redirect"""
        self.user_ent.testing_create(email='foo@bar.com', password='pass')

        # unquoted next parameter
        next = 'http://www.example.com'
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('{}?next={}'.format(
            flask.url_for(flask.current_app.auth_manager.endpoint('login')), next
            )
        )

        resp.form['login_id'] = 'foo@bar.com'
        resp.form['password'] = 'pass'
        resp = resp.form.submit()

        assert resp.status_code == 302, resp.html
        # verify the 'next' parameter was ignored
        assert resp.headers['Location'] == flask.url_for(
            flask.current_app.auth_manager.endpoint('after-login')
        )
        flash_success = flask.current_app.auth_manager.login_authenticator_cls.responder_cls['login'].flash_success  # noqa
        category = flash_success[1]
        message = flash_success[0]
        assert resp.flashes == [(category, message)]

        # quoted next parameter
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('{}?next={}'.format(
            flask.url_for(flask.current_app.auth_manager.endpoint('login')),
            urllib.parse.quote(next)
            )
        )

        resp.form['login_id'] = 'foo@bar.com'
        resp.form['password'] = 'pass'
        resp = resp.form.submit()

        assert resp.status_code == 302, resp.html
        # verify the 'next' parameter was ignored
        assert resp.headers['Location'] == flask.url_for(
            flask.current_app.auth_manager.endpoint('after-login')
        )
        flash_success = flask.current_app.auth_manager.login_authenticator_cls.responder_cls['login'].flash_success  # noqa
        category = flash_success[1]
        message = flash_success[0]
        assert resp.flashes == [(category, message)]

    def test_login_invalid_password(self):
        self.user_ent.testing_create(email='foo@bar.com', password='pass')

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('login')))

        resp.form['login_id'] = 'foo@bar.com'
        resp.form['password'] = 'badpass'
        resp = resp.form.submit(status=200)

        flash_invalid_password = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['login'].flash_invalid_password
        category = flash_invalid_password[1]
        message = flash_invalid_password[0]
        assert resp.flashes == [(category, message)]

    def test_login_user_missing(self):
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('login')))

        resp.form['login_id'] = 'foo@bar.com'
        resp.form['password'] = 'badpass'
        resp = resp.form.submit(status=200)

        flash_invalid_user = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['login'].flash_invalid_user
        category = flash_invalid_user[1]
        message = flash_invalid_user[0]
        assert resp.flashes == [(category, message.format('foo@bar.com'))]

    def test_login_user_unverified(self):
        self.user_ent.testing_create(email='foo@bar.com', password='pass', is_verified=False)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('login')))

        resp.form['login_id'] = 'foo@bar.com'
        resp.form['password'] = 'badpass'
        resp = resp.form.submit(status=200)

        flash_unverified_user = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['login'].flash_unverified_user
        category = flash_unverified_user[1]
        message = flash_unverified_user[0]
        assert resp.flashes == [(category, message.format('foo@bar.com'))]

    def test_login_user_disabled(self):
        self.user_ent.testing_create(email='foo@bar.com', password='pass', is_enabled=False)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('login')))

        resp.form['login_id'] = 'foo@bar.com'
        resp.form['password'] = 'badpass'
        resp = resp.form.submit(status=200)

        flash_disabled_user = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['login'].flash_disabled_user
        category = flash_disabled_user[1]
        message = flash_disabled_user[0]
        assert resp.flashes == [(category, message.format('foo@bar.com'))]

    def test_login_protection(self):
        self.user_ent.testing_create(
            email='foo@bar.com', password='pass', permissions=self.protected_url_permissions
        )

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(self.protected_url, status=302)
        full_login_url = 'http://keg.example.com{}'.format(
            urlparse(flask.url_for(flask.current_app.auth_manager.endpoint('login'))).path
        )
        assert resp.headers['Location'].startswith(full_login_url)

        resp = resp.follow()
        resp.form['login_id'] = 'foo@bar.com'
        resp.form['password'] = 'pass'
        resp = resp.form.submit(status=302)
        flash_success = flask.current_app.auth_manager.login_authenticator_cls.responder_cls['login'].flash_success  # noqa
        category = flash_success[1]
        message = flash_success[0]
        assert resp.flashes == [(category, message)]

        # Now that we have logged in, we should be able to get to the page.
        client.get(self.protected_url, status=200)

    def test_forgot_pw_form_error(self):
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('forgot-password')))
        resp = resp.form.submit(status=200)

        flash_form_error = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['forgot-password'].flash_form_error
        category = flash_form_error[1]
        message = flash_form_error[0]
        assert resp.flashes == [(category, message)]

    def test_forgot_pw_invalid_user(self):
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('forgot-password')))

        resp.form['email'] = 'foo@bar.com'
        resp = resp.form.submit(status=200)

        flash_invalid_user = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['forgot-password'].flash_invalid_user
        category = flash_invalid_user[1]
        message = flash_invalid_user[0]
        assert resp.flashes == [(category, message.format('foo@bar.com'))]

    def test_forgot_pw_user_disabled(self):
        self.user_ent.testing_create(email='foo@bar.com', password='pass', is_enabled=False)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('forgot-password')))

        resp.form['email'] = 'foo@bar.com'
        resp = resp.form.submit(status=200)

        flash_disabled_user = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['forgot-password'].flash_disabled_user
        category = flash_disabled_user[1]
        message = flash_disabled_user[0]
        assert resp.flashes == [(category, message.format('foo@bar.com'))]

    def test_forgot_pw_success(self):
        self.user_ent.testing_create(email='foo@bar.com')

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('forgot-password')))

        resp.form['email'] = 'foo@bar.com'
        resp = resp.form.submit(status=302)

        flash_success = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['forgot-password'].flash_success
        category = flash_success[1]
        message = flash_success[0]
        assert resp.flashes == [(category, message)]

        full_login_url = 'http://keg.example.com{}'.format(
            urlparse(flask.url_for(flask.current_app.auth_manager.endpoint('login'))).path
        )
        assert resp.headers['Location'] == full_login_url

    def test_reset_pw_success(self):
        user = self.user_ent.testing_create()
        token = user.token_generate()
        url = flask.url_for(flask.current_app.auth_manager.endpoint('reset-password'),
                            user_id=user.id, token=token)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url, status=200)

        resp.form['password'] = 'foo'
        resp.form['confirm'] = 'foo'
        resp = resp.form.submit(status=302)

        flash_success = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['reset-password'].flash_success
        category = flash_success[1]
        message = flash_success[0]
        assert resp.flashes == [(category, message)]

        full_login_url = 'http://keg.example.com{}'.format(
            urlparse(flask.url_for(flask.current_app.auth_manager.endpoint('login'))).path
        )
        assert resp.headers['Location'] == full_login_url

    def test_reset_pw_form_error(self):
        user = self.user_ent.testing_create()
        token = user.token_generate()
        url = flask.url_for(flask.current_app.auth_manager.endpoint('reset-password'),
                            user_id=user.id, token=token)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url, status=200)
        resp = resp.form.submit(status=200)

        flash_form_error = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['reset-password'].flash_form_error
        category = flash_form_error[1]
        message = flash_form_error[0]
        assert resp.flashes == [(category, message)]

    def test_reset_pw_missing_user(self):
        url = flask.url_for(flask.current_app.auth_manager.endpoint('reset-password'),
                            user_id='99999999', token='123')

        client = flask_webtest.TestApp(flask.current_app)
        client.get(url, status=404)

    def test_reset_pw_bad_token(self):
        user = self.user_ent.testing_create()
        url = flask.url_for(flask.current_app.auth_manager.endpoint('reset-password'),
                            user_id=user.id, token='abc')

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url, status=302)

        flash_invalid_token = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['reset-password'].flash_invalid_token
        category = flash_invalid_token[1]
        message = flash_invalid_token[0]
        assert resp.flashes == [(category, message)]

        full_forgot_password_url = 'http://keg.example.com{}'.format(
            urlparse(flask.url_for(flask.current_app.auth_manager.endpoint('forgot-password'))).path
        )
        assert resp.headers['Location'] == full_forgot_password_url

    def test_verify_account_success(self):
        user = self.user_ent.testing_create(is_verified=False)
        assert not user.is_verified

        user.token_generate()
        url = flask.current_app.auth_manager.mail_manager.verify_account_url(user)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url, status=200)

        resp.form['password'] = 'foo'
        resp.form['confirm'] = 'foo'
        resp = resp.form.submit(status=302)

        flash_success = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['verify-account'].flash_success
        category = flash_success[1]
        message = flash_success[0]
        assert resp.flashes == [(category, message)]

        full_login_url = 'http://keg.example.com{}'.format(
            urlparse(flask.url_for(flask.current_app.auth_manager.endpoint('login'))).path
        )
        assert resp.headers['Location'] == full_login_url

        assert user.is_verified

    def test_verify_account_form_error(self):
        user = self.user_ent.testing_create()
        user.token_generate()
        url = flask.current_app.auth_manager.mail_manager.verify_account_url(user)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url, status=200)
        resp = resp.form.submit(status=200)

        flash_form_error = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['verify-account'].flash_form_error
        category = flash_form_error[1]
        message = flash_form_error[0]
        assert resp.flashes == [(category, message)]

    def test_verify_account_missing_user(self):
        user = LazyDict(id=9999999, _token_plain='123')
        url = flask.current_app.auth_manager.mail_manager.verify_account_url(user)

        client = flask_webtest.TestApp(flask.current_app)
        client.get(url, status=404)

    def test_verify_account_bad_token(self):
        user = self.user_ent.testing_create()
        user._token_plain = 'abc'
        url = flask.current_app.auth_manager.mail_manager.verify_account_url(user)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url, status=302)

        flash_invalid_token = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['verify-account'].flash_invalid_token
        category = flash_invalid_token[1]
        message = flash_invalid_token[0]
        assert resp.flashes == [(category, message)]

        full_forgot_password_url = 'http://keg.example.com{}'.format(
            urlparse(flask.url_for(flask.current_app.auth_manager.endpoint('forgot-password'))).path
        )
        assert resp.headers['Location'] == full_forgot_password_url

    def test_logout(self):
        user = self.user_ent.testing_create(permissions=self.protected_url_permissions)
        client = flask_webtest.TestApp(flask.current_app)
        with client.session_transaction() as sess:
            sess['user_id'] = user.session_key

        # Make sure our client is actually logged in
        client.get(self.protected_url, status=200)

        # logout
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('logout')),
                          status=302)
        assert resp.flashes == [('success', 'You have been logged out.')]

        # Check redirect location
        full_after_logout_url = flask.url_for(flask.current_app.auth_manager.
                                              endpoint('after-logout'))
        assert resp.headers['Location'] == full_after_logout_url

        # Confirm logout occured
        client.get(self.protected_url, status=302)


@wrapt.decorator
def user_request(wrapped, instance, args, kwargs):
    new_kwargs = kwargs.copy()
    user = new_kwargs.pop('user', None)
    extra_environ = new_kwargs.setdefault('extra_environ', {})
    if user is not None:
        extra_environ['TEST_USER_ID'] = str(user.session_key)
    return wrapped(*args, **new_kwargs)


def with_crypto_context(field, context=None):
    """Wrap a test to use a real cryptographic context for a :class:`KAPasswordType`

    Temporarily assign a :class:`passlib.context.CryptoContext` to a particular entity column.

    :param context (optional): :class:`passlib.context.CryptoContext` to use for this test. The
        default value is `keg_auth.core.DEFAULT_CRYPTO_SCHEMES`.

    .. NOTE: In most situations we don't want a real crypto scheme to run in the tests, it is
    slow on entities like Users which have a password. ``User.testing_create`` will generate a value
    for that instance and then hash which takes a bunch of time. However, when testing certain
    schemes, it is useful to execute the real behavior instead of the ``plaintext`` behaviour.

    ::

        import bcrypt

        bcrypt_context = passlib.context.CryptContext(scheme=['bcrypt'])

        @with_crypto_context(ents.User.password, context=bcrypt_context)
        def test_with_real_context():
            user = ents.User.testing_create(password='abc')
            assert bcrypt.checkpw('abc', user.password.hash)

    """
    import keg_auth

    @wrapt.decorator
    def wrapper(wrapped, instance, args, kwargs):
        prev_context = field.type.context
        field.type.context = (
            context or passlib.context.CryptContext(schemes=keg_auth.core.DEFAULT_CRYPTO_SCHEMES)
        )

        wrapped(*args, **kwargs)

        field.type.context = prev_context

    return wrapper


class AuthTestApp(flask_webtest.TestApp):
    def __init__(self, app, **kwargs):
        user = kwargs.pop('user', None)
        extra_environ = kwargs.pop('extra_environ', {})
        if user is not None:
            extra_environ['TEST_USER_ID'] = str(user.session_key)
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
        cls.user_ent = flask.current_app.auth_manager.entity_registry.user_cls
        cls.permission_ent = flask.current_app.auth_manager.entity_registry.permission_cls
        cls.user_ent.delete_cascaded()

        # ensure all of the tokens exists
        defined_perms = set(
            tolist(perm)[0] for perm in flask.current_app.auth_manager.permissions
        )
        for perm in tolist(cls.permissions):
            if perm not in defined_perms:
                raise Exception('permission {} not specified in the auth manager'.format(perm))
            cls.permission_ent.testing_create(token=perm)

        cls.current_user = cls.user_ent.testing_create(permissions=cls.permissions)
        cls.client = AuthTestApp(flask.current_app, user=cls.current_user)
