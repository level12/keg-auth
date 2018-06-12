Keg Auth’s Readme
==========================================

.. image:: https://circleci.com/gh/level12/keg-auth.svg?&style=shield&circle-token=b90c5336d179f28df73d404a26924bc373840257
    :target: https://circleci.com/gh/level12/keg-auth

.. image:: https://codecov.io/github/level12/keg-auth/coverage.svg?branch=master&token=hl15MQRPeF
    :target: https://codecov.io/github/level12/keg-auth?branch=master

Demo
----

Typical usage is demonstrated in
https://github.com/level12/keg-app-cookiecutter

Usage
-----

-  Blueprints

   -  include an auth blueprint along with your app’s blueprints:

.. code-block:: python

          from keg_auth import make_blueprint
          auth_bp = make_blueprint(__name__)

-  Extensions

   -  set up an auth manager (in app setup or extensions)

.. code-block:: python

          mail_ext = Mail()
          _endpoints = {'after-login': 'public.home'}
          auth_manager = AuthManager(mail_ext, endpoints=_endpoints)
          auth_manager.init_app(app)


   -  CLI is rudimentary, with just one create-user command in the auth group. You can extend the
      group by using the cli_group attribute on the app's auth_manager, but you need access to the
      app during startup to do that. You can use an event signal to handle this - just be sure
      your app's `visit_modules` has the location of the event.

.. code-block:: python

          # in app definition
          visit_modules = ['.events']


          # in events module
          from keg.signals import app_ready

          from keg_auth_ta.cli import auth_cli_extensions


          @app_ready.connect
          def init_app_cli(app):
              auth_cli_extensions(app)


          # in cli
          def auth_cli_extensions(app):
              @app.auth_manager.cli_group.command('command-extension')
              def command_extension():
                  pass

   -  CLI create-user command, by default, has one required argument (email). If you wish to have
      additional arguments, put the list of arg names in `KEGAUTH_CLI_USER_ARGS` config

-  Model

   -  create entities using the existing mixins, and register them with
      keg_auth
   -  note: the User model assumes that the entity mixed with UserMixin
      will have a PK id

.. code-block:: python

          from keg.db import db
          from keg_elements.db.mixins import DefaultColsMixin, MethodsMixin
          from keg_auth.model.entity_registry import registry
          from keg_auth import UserMixin, PermissionMixin, BundleMixin, GroupMixin


          class EntityMixin(DefaultColsMixin, MethodsMixin):
              pass


          @registry.register_user
          class User(db.Model, UserMixin, EntityMixin):
              __tablename__ = 'users'


          @registry.register_permission
          class Permission(db.Model, PermissionMixin, EntityMixin):
              __tablename__ = 'permissions'

              def __repr__(self):
                  return '<Permission id={} token={}>'.format(self.id, self.token)


          @registry.register_bundle
          class Bundle(db.Model, BundleMixin, EntityMixin):
              __tablename__ = 'bundles'


          @registry.register_group
          class Group(db.Model, GroupMixin, EntityMixin):
              __tablename__ = 'groups'

-  Views

   -  views may be restricted for access using the requires\* decorators
   -  each decorator can be used as a class decorator or on individual
      view methods
   -  ``requires_user``

      -  require a user to be authenticated before proceeding
         (authentication only)
      -  usage: ``@requires_user`` or ``@requires_user()`` (both usage
         patterns are identical)
      -  note: this is similar to ``flask_login.login_required``, but
         can be used as a class decorator

   -  ``requires_permissions``

      -  require a user to be conditionally authorized before proceeding
         (authentication + authorization)
      -  ``has_any`` and ``has_all`` helpers can be used to construct
         complex conditions, using string permission tokens, nested
         helpers, and callable methods
      -  usage:

         -  ``@requires_permissions(('token1', 'token2'))``
         -  ``@requires_permissions(has_any('token1', 'token2'))``
         -  ``@requires_permissions(has_all('token1', 'token2'))``
         -  ``@requires_permissions(has_all(has_any('token1', 'token2'), 'token3'))``
         -  ``@requires_permissions(custom_authorization_callable that takes user arg)``

User Login During Testing
-------------------------

This library provides ``keg_auth.testing.AuthTestApp`` which is a
sub-class of ``flask_webtest.TestApp`` to make it easy to set the
logged-in user during testing:

.. code-block:: python

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
            client.get('/secret-page', status=302)

For having a user with permissions logged in for tests, the
``login_client_with_permissions`` helper is provided. Note: the
developer is responsible to ensure token strings provided are in the
database.

.. code-block:: python

    from keg_auth.testing import login_client_with_permissions

    # can be called with token strings, Permission instances, or both
    # returns a tuple with an AuthTestApp instance and a User instance
    client, user = login_client_with_permissions('permission1', 'permission2', ...)

A helper class is also provided to set up a client and user, given the
permissions specified on the class definition:

.. code-block:: python

    from keg_auth.testing import ViewTestBase

    class TestMyView(ViewTestBase):
        permissions = 'permission1', 'permission2', ...

        def test_get(self):
            self.client.get('/foo')
