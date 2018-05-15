.. default-role:: code

Keg Auth's Readme
######################################

.. image:: https://circleci.com/gh/level12/keg-auth.svg?&style=shield&circle-token=b90c5336d179f28df73d404a26924bc373840257
    :target: https://circleci.com/gh/level12/keg-auth

.. image:: https://codecov.io/github/level12/keg-auth/coverage.svg?branch=master&token=hl15MQRPeF
    :target: https://codecov.io/github/level12/keg-auth?branch=master


Demo
=======================

Typical usage is demonstrated in https://github.com/level12/keg-app-cookiecutter


User Login During Testing
=========================

This library provides `keg_auth.testing.AuthTestApp` which is a sub-class of `flask_webtest.TestApp`
to makes it easy to set the logged-in user during testing::

    from keg_auth.testing import AuthTestApp

    class TestViews(object):
        def setup(self):
            ents.User.delete_cascaded()
    
        def test_authenticated_client(self):
            """
                Demonstrate logging in at the client level.  The login will apply to all requests made
                by this client.
            """
            user = ents.User.testing_create()
            client = AuthTestApp(flask.current_app, user=user)
            resp = client.get('/secret2', status=200)
            assert resp.text == 'secret2'
    
        def test_authenticated_request(self):
            """
                Demonstrate logging in at the request level.  The login will only apply to one request.
            """
            user = ents.User.testing_create()
            client = AuthTestApp(flask.current_app)
    
            resp = client.get('/secret-page', status=200, user=user)
            assert resp.text == 'secret-page'
    
            # User should only stick around for a single request (and will get a 302 redirect to the)
            # login view.
            client.get('/secrete-page', status=302)
