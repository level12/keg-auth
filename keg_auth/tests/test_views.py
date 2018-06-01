# Using unicode_literals instead of adding 'u' prefix to all stings that go to SA.
from __future__ import unicode_literals

import flask
import flask_webtest
from keg.db import db

from keg_auth.testing import AuthTests, AuthTestApp, ViewTestBase
import mock

from keg_auth_ta.model import entities as ents


class TestAuthIntegration(AuthTests):
    user_ent = ents.User


class TestViews(object):
    """
        Basic functionality is tested through AuthTests.  The tests in this class cover
        functionality that is specific to the default implementation but might fail depending on
        what customization is made.
    """

    @classmethod
    def setup_class(cls):
        ents.Permission.delete_cascaded()
        cls.perm1 = ents.Permission.testing_create(token='permission1')
        cls.perm2 = ents.Permission.testing_create(token='permission2')

    def setup(self):
        ents.User.delete_cascaded()

    def test_home(self):
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/')
        assert 'Keg Auth Demo' in resp
        assert '/login' in resp
        assert '/logout' not in resp

        user = ents.User.testing_create()
        with client.session_transaction() as sess:
            sess['user_id'] = user.id

        resp = client.get('/')
        assert '/login' not in resp
        assert '/logout' in resp

    def test_auth_base_view(self):
        ents.User.testing_create(email='foo@bar.com', password='pass',
                                 permissions=[self.perm1, self.perm2])

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/secret2', status=302)

        resp = resp.follow()
        resp.form['email'] = 'foo@bar.com'
        resp.form['password'] = 'pass'
        resp = resp.form.submit(status=302)
        assert resp.flashes == [('success', 'Login successful.')]

        # Now that we have logged in, we should be able to get to the page.
        resp = client.get('/secret2', status=200)
        assert resp.text == 'secret2'

    def test_authenticated_client(self):
        user = ents.User.testing_create()
        client = AuthTestApp(flask.current_app, user=user)
        resp = client.get('/secret1', status=200)
        assert resp.text == 'secret1'

        resp = client.get('/secret1-class', status=200)
        assert resp.text == 'secret1-class'

    def test_unauthenticated_client(self):
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/secret1', status=302)
        assert '/login' in resp.location
        resp = client.get('/secret1-class', status=302)
        assert '/login' in resp.location

    def test_authenticated_request(self):
        user = ents.User.testing_create(permissions=[self.perm1, self.perm2])
        client = AuthTestApp(flask.current_app)

        resp = client.get('/secret2', status=200, user=user)
        assert resp.text == 'secret2'

        # User should only stick around for a single request
        client.get('/secret2', status=302)

        # test all HTTP methods
        assert client.post('/secret2', status=200, user=user).text == 'secret2 post'
        assert client.put('/secret2', status=200, user=user).text == 'secret2 put'
        assert client.patch('/secret2', status=200, user=user).text == 'secret2 patch'
        assert client.delete('/secret2', status=200, user=user).text == 'secret2 delete'
        assert client.options('/secret2', status=200, user=user).text == 'secret2 options'
        assert client.head('/secret2', status=200, user=user)
        assert client.post_json('/secret2', status=200, user=user).text == 'secret2 post'
        assert client.put_json('/secret2', status=200, user=user).text == 'secret2 put'
        assert client.patch_json('/secret2', status=200, user=user).text == 'secret2 patch'
        assert client.delete_json('/secret2', status=200, user=user).text == 'secret2 delete'

    def test_login_template(self):
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/login')
        doc = resp.pyquery
        assert doc('title').text() == 'Log In | Keg Auth Demo'
        assert doc('h1').text() == 'Log In'
        assert doc('button').text() == 'Log In'
        assert doc('a').text() == 'I forgot my password'
        assert doc('a').attr('href') == '/forgot-password'

    def test_forgot_pw_template(self):
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/forgot-password')
        doc = resp.pyquery
        assert doc('title').text() == 'Initiate Password Reset | Keg Auth Demo'
        assert doc('h1').text() == 'Initiate Password Reset'
        assert doc('button').text() == 'Send Reset Email'
        assert doc('a').text() == 'Cancel'
        assert doc('a').attr('href') == '/login'

    @mock.patch('keg_auth.views.flask.current_app.auth_mail_manager.send_reset_password',
                autospec=True, spec_set=True)
    def test_forget_pw_actions(self, m_send_reset_password):
        user = ents.User.testing_create(email='foo@bar.com')

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/forgot-password')
        resp.form['email'] = 'foo@bar.com'
        resp = resp.form.submit(status=302)

        # email should be sent
        m_send_reset_password.assert_called_once_with(user)

        # Make sure db updates got committed
        db.session.expire(user)
        assert user.token is not None
        assert user.token_created_utc is not None

    def test_reset_pw_template(self):
        user = ents.User.testing_create()
        user.token_generate()
        url = flask.current_app.auth_manager.reset_password_url(user)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url)
        doc = resp.pyquery
        assert doc('title').text() == 'Complete Password Reset | Keg Auth Demo'
        assert doc('h1').text() == 'Complete Password Reset'
        assert doc('button').text() == 'Change Password'
        assert doc('a').text() == 'Cancel'
        assert doc('a').attr('href') == '/login'

    def test_reset_pw_actions(self):
        user = ents.User.testing_create()
        token = user.token_generate()

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/reset-password/{}/{}'.format(user.id, token))
        resp.form['password'] = resp.form['confirm'] = 'foobar'
        resp = resp.form.submit(status=302)

        # Make sure db updates got committed
        db.session.expire(user)
        assert user.token is None
        assert user.password == 'foobar'

    def test_verify_account_template(self):
        user = ents.User.testing_create()
        user.token_generate()
        url = flask.current_app.auth_manager.verify_account_url(user)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url)
        doc = resp.pyquery
        assert doc('title').text() == 'Verify Account & Set Password | Keg Auth Demo'
        assert doc('h1').text() == 'Verify Account & Set Password'
        assert doc('button').text() == 'Verify & Set Password'
        assert doc('a').text() == 'Cancel'
        assert doc('a').attr('href') == '/login'


class TestPermissionsRequired:
    @classmethod
    def setup_class(cls):
        ents.Permission.delete_cascaded()
        cls.perm1 = ents.Permission.testing_create(token='permission1')
        cls.perm2 = ents.Permission.testing_create(token='permission2')
        cls.perm3 = ents.Permission.testing_create(token='permission3')

    def test_method_level(self):
        allowed = ents.User.testing_create(permissions=[self.perm1, self.perm2])
        disallowed = ents.User.testing_create(permissions=[self.perm1])

        client = AuthTestApp(flask.current_app, user=allowed)
        resp = client.get('/secret2', status=200)
        assert resp.text == 'secret2'

        client = AuthTestApp(flask.current_app, user=disallowed)
        client.post('/secret2', {}, status=403)

    def test_class_level(self):
        allowed = ents.User.testing_create(permissions=[self.perm1, self.perm2])
        disallowed = ents.User.testing_create(permissions=[self.perm1])

        client = AuthTestApp(flask.current_app, user=allowed)
        resp = client.get('/secret3', status=200)
        assert resp.text == 'secret3'

        client = AuthTestApp(flask.current_app, user=disallowed)
        client.get('/secret3', {}, status=403)

        client = flask_webtest.TestApp(flask.current_app)
        client.get('/secret3', status=302)

    def test_nested_conditions(self):
        def check(perms, allowed):
            print(perms, allowed)
            target_status = 200 if allowed else 403
            user = ents.User.testing_create(permissions=perms)

            client = AuthTestApp(flask.current_app, user=user)
            resp = client.get('/secret-nested', status=target_status)
            if allowed:
                assert resp.text == 'secret_nested'

        for perms, allowed in (
            ((self.perm1, self.perm2), True),
            ((self.perm3,), True),
            ((self.perm1,), False),
            ((self.perm2,), False),
            ((self.perm1, self.perm2, self.perm3), True),
        ):
            check(perms, allowed)

    def test_nested_callable_conditions(self):
        def check(perms, email, allowed):
            print(perms, email, allowed)
            ents.User.delete_cascaded()
            target_status = 200 if allowed else 403
            user = ents.User.testing_create(permissions=perms, email=email)

            client = AuthTestApp(flask.current_app, user=user)
            resp = client.get('/secret-nested-callable', status=target_status)
            if allowed:
                assert resp.text == 'secret_nested_callable'

        for perms, email, allowed in (
            ((self.perm1,), 'snoopy@peanuts.com', True),
            ((self.perm2,), 'snoopy@peanuts.com', False),
            ((self.perm2,), 'foo@bar.baz', True),
        ):
            check(perms, email, allowed)

    def test_callable_conditions(self):
        def check(email, allowed):
            print(email, allowed)
            ents.User.delete_cascaded()
            target_status = 200 if allowed else 403
            user = ents.User.testing_create(email=email)

            client = AuthTestApp(flask.current_app, user=user)
            resp = client.get('/secret-callable', status=target_status)
            if allowed:
                assert resp.text == 'secret_callable'

        for email, allowed in (
            ('snoopy@peanuts.com', False),
            ('foo@bar.baz', True),
        ):
            check(email, allowed)


class TestUserCrud(ViewTestBase):
    permissions = 'auth-manage'

    def test_add(self):
        resp = self.client.get('/users/add')

        assert resp.form['email'].value == ''
        assert 'is_superuser' not in resp.form.fields

        resp.form['email'] = 'abc@example.com'
        resp = resp.form.submit()
        assert resp.status_code == 302
        assert resp.location.endswith('/users')
        assert resp.flashes == [('success', 'Successfully created User')]

        user = self.user_ent.get_by(email='abc@example.com')
        assert user.is_enabled is True
        assert user.is_superuser is False
