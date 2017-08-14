import flask
import flask_webtest
from keg.db import db
from kegauth.testing import AuthTests
import mock

from kegauth_ta.model import entities as ents


class TestAuthIntegration(AuthTests):
    user_ent = ents.User


class TestViews:
    """
        Basic functionality is tested through AuthTests.  The tests in this class cover
        functionality that is specific to the default implementation but might fail depending on
        what customization is made.
    """

    @classmethod
    def setup_class(cls):
        cls.ta = flask_webtest.TestApp(flask.current_app)

    def setup(self):
        ents.User.delete_cascaded()

    def test_home(self):
        resp = self.ta.get('/')
        assert 'Keg Auth Demo' in resp
        assert '/login' in resp

    def test_auth_base_view(self):
        ents.User.testing_create(email='foo@bar.com', password='pass')

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

    def test_login_template(self):
        resp = self.ta.get('/login')
        doc = resp.pyquery
        assert doc('title').text() == 'Log In | Keg Auth Demo'
        assert doc('h1').text() == 'Log In'
        assert doc('button').text() == 'Log In'
        assert doc('a').text() == 'I forgot my password'
        assert doc('a').attr('href') == '/forgot-password'

    def test_forgot_pw_template(self):
        resp = self.ta.get('/forgot-password')
        doc = resp.pyquery
        assert doc('title').text() == 'Initiate Password Reset | Keg Auth Demo'
        assert doc('h1').text() == 'Initiate Password Reset'
        assert doc('button').text() == 'Send Reset Email'
        assert doc('a').text() == 'Cancel'
        assert doc('a').attr('href') == '/login'

    @mock.patch('kegauth.views.flask.current_app.auth_mail_manager.send_reset_password',
                autospec=True, spec_set=True)
    def test_forget_pw_actions(self, m_send_reset_password):
        user = ents.User.testing_create(email='foo@bar.com')

        resp = self.ta.get('/forgot-password')
        resp.form['email'] = 'foo@bar.com'
        resp = resp.form.submit(status=302)

        # email should be sent
        m_send_reset_password.assert_called_once_with(user)

        # Make sure db updates got committed
        db.session.expire(user)
        assert user.token is not None
        assert user.token_created_utc is not None

    def test_reset_pw_actions(self):
        user = ents.User.testing_create()
        token = user.token_generate()

        resp = self.ta.get('/reset-password/{}/{}'.format(user.id, token))
        resp.form['password'] = resp.form['confirm'] = 'foobar'
        resp = resp.form.submit(status=302)

        # Make sure db updates got committed
        db.session.expire(user)
        assert user.token is None
        assert user.password == 'foobar'
