import flask
import flask_webtest
from kegauth.testing import AuthTests

from kegauth_ta.model import entities as ents


class TestAuthIntegration(AuthTests):
    user_ent = ents.User


class TestViews:

    def setup(self):
        ents.User.delete_cascaded()

    def test_home(self):
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/')
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

