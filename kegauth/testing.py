import flask
import flask_webtest


class AuthTests:
    """
        These tests are designed so they can can be imported into an application's tests
        and ran to ensure customization of KegAuth hasn't broken basic functionality.

        TODO: the messages we test for need to be configurable on the class in case the app
        customizes then.
    """
    login_url = '/login'
    protected_url = '/secret1'
    forgot_password_url = '/forgot-password'
    reset_password_url = '/reset-password'

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
        url = '/{}/{}/{}'.format(self.reset_password_url, user.id, token)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url, status=200)
        resp = resp.form.submit(status=200)

        assert resp.flashes == [('error', 'The form has errors, please see below.')]

    def test_reset_pw_missing_user(self):
        url = '/{}/99999999/123'.format(self.reset_password_url)

        client = flask_webtest.TestApp(flask.current_app)
        client.get(url, status=404)

    def test_reset_pw_bad_token(self):
        user = self.user_ent.testing_create()
        url = '/{}/{}/abc'.format(self.reset_password_url, user.id)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url, status=302)

        msg = 'Password reset token was invalid or expired.  Please try again.'
        assert resp.flashes == [('error', msg)]

        full_login_url = 'http://keg.example.com{}'.format(self.forgot_password_url)
        assert resp.headers['Location'] == full_login_url
