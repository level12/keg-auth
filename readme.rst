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

   -  include an auth blueprint along with your app’s blueprints, which includes the login views
      and user/group/bundle management:

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

   -  Authenticators control validation of users
      -  'keg' is the default primary authenticator, and uses username/password
      -  authenticators may be registered on the auth_manager:
         -  ``AuthManager(mail_ext, primary_authenticator_cls=JwtAuthenticator)``
         -  ``AuthManager(mail_ext, secondary_authenticators=[JwtAuthenticator, LdapAuthenticator])``
      -  token authenticators, like JwtAuthenticator, have a `create_access_token` method
         -  ``token = auth_manager.get_authenticator('jwt').create_access_token(user)``
      -  JWT authentication uses flask-jwt-extended, which needs to be installed:
         -  ``pip install keg-auth[jwt]``

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
          from keg_auth import UserMixin, PermissionMixin, BundleMixin, GroupMixin, auth_entity_registry


          class EntityMixin(DefaultColsMixin, MethodsMixin):
              pass


          @auth_entity_registry.register_user
          class User(db.Model, UserMixin, EntityMixin):
              __tablename__ = 'users'


          @auth_entity_registry.register_permission
          class Permission(db.Model, PermissionMixin, EntityMixin):
              __tablename__ = 'permissions'

              def __repr__(self):
                  return '<Permission id={} token={}>'.format(self.id, self.token)


          @auth_entity_registry.register_bundle
          class Bundle(db.Model, BundleMixin, EntityMixin):
              __tablename__ = 'bundles'


          @auth_entity_registry.register_group
          class Group(db.Model, GroupMixin, EntityMixin):
              __tablename__ = 'groups'

-  Navigation Helpers

   -  Keg-Auth provides navigation helpers to set up a menu tree, for which nodes on the tree are
      restricted according to the authentication/authorization requirements of the target endpoint
   -  Usage involves setting up a menu structure with Node/Route objects. Note that permissions on
      a route may be overridden for navigation purposes
   -  Menus may be tracked on the auth manager, which will reset their cached access on
      login/logout
   -  `keg_auth/navigation.html` template has a helper `render_menu` to render a given menu as a ul
      -  `render_menu(auth_manager.menus['main'])`
   -  Example:

.. code-block:: python

          from keg.signals import app_ready

          from keg_auth import Node, Route

          @app_ready.connect
          def init_navigation(app):
              app.auth_manager.add_navigation_menu(
                  'main',
                  Node(
                      Node('Home', Route('public.home')),
                      Node(
                          'Nesting',
                          Node('Secret1', Route('private.secret1')),
                          Node('Secret1 Class', Route('private.secret1-class')),
                      ),
                      Node('Permissions On Stock Methods', Route('private.secret2')),
                      Node('Permissions On Methods', Route('private.someroute')),
                      Node('Permissions On Class And Method', Route('private.secret4')),
                      Node('Permissions On Route',
                           Route(
                               'private.secret3', requires_permissions='permission3'
                           )),
                      Node('User Manage', Route('auth.user:add')),
                  )
              )


-  Views

   -  views may be restricted for access using the requires\* decorators
   -  each decorator can be used as a class decorator or on individual
      view methods
   -  additionally, the decorator may be used on a Blueprint to apply the requirement to all
      routes on the blueprint
   -  ``requires_user``

      -  require a user to be authenticated before proceeding
         (authentication only)
      -  usage: ``@requires_user`` or ``@requires_user()`` (both usage
         patterns are identical if no secondary authenticators are needed)
      -  note: this is similar to ``flask_login.login_required``, but
         can be used as a class decorator
      -  the decorator uses authenticators to determine whether a user is logged in
         -  the primary authenticator is used by default
         -  control a view/blueprint's authenticators by specifying them on the decorator:
            -  ``@requires_user(authenticators='jwt')``
            -  ``@requires_user(authenticators=['keg', 'jwt'])``

   -  ``requires_permissions``

      -  require a user to be conditionally authorized before proceeding
         (authentication + authorization)
      -  ``has_any`` and ``has_all`` helpers can be used to construct
         complex conditions, using string permission tokens, nested
         helpers, and callable methods
      -  authenticators are used as in `requires_user`
      -  usage:

         -  ``@requires_permissions(('token1', 'token2'))``
         -  ``@requires_permissions(('token1', 'token2'), authenticators='jwt')``
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
