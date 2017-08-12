import flask
import flask_webtest


class AuthTests:
    login_url = '/login'
    protected_url = '/secret1'

    def setup(self):
        self.user_ent.delete_cascaded()

    def test_login_get(self):
        app = flask.current_app
        client = flask_webtest.TestApp(app)
        resp = client.get(self.login_url)
        assert resp.status_code == 200

    def test_login_field_error(self):
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

