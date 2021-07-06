Getting Started
===============

.. contents::
    :local:

.. _gs-install:

Installation
------------

- Bare functionality: `pip install keg-auth`
- With mail (i.e. with a mail manager configured, see below): `pip install keg-auth[mail]`
- JWT (for using JWT tokens as authenticators): `pip install keg-auth[jwt]`
- LDAP (for using LDAP target for authentication): `pip install keg-auth[ldap]`
- OIDC (for OAuth, e.g. Okta or Auth0): `pip install keg-auth[oidc]`
- Internationalization extensions: `pip install keg-auth[i18n]`


.. _gs-config:

Configuration
-------------

-  ``SERVER_NAME = 'somehost'``: Required for Keg Auth when generating URL in create-user CLI command

    -  include a port number if needed (e.g. `localhost:5000`)

-  ``PREFERRED_URL_SCHEME = 'https'``: This is important so that generated auth related URLS are
    secure.  You could have an SSL redirect but by the time that would fire, the key would
    have already been sent in the URL.
-  ``KEGAUTH_TOKEN_EXPIRE_MINS``: Integer, defaults to 240 minutes (4 hours)

    -  If mail functions are enabled and tokens in the model, affects the time a verification token remains valid

-  ``KEGAUTH_CLI_USER_ARGS``: List of strings, defaults to `['email']`

    -  Names arguments to be accepted by CLI user commands and passed to the model

- ``KEGAUTH_HTTP_METHODS_EXCLUDED``: List of HTTP methods to exclude from auth checks

    -  Useful for CORS-applicable situations, where it may be advantageous to respond normally
       to an OPTIONS request. Then, auth will apply as expected on the ensuing GET/POST/PUT/etc.

-  Email settings

    -  ``KEGAUTH_EMAIL_SITE_NAME = 'Keg Application'``: Used in email body if mail is enabled
    -  ``KEGAUTH_EMAIL_SITE_ABBR = 'Keg App'``: Used in email subject if mail is enabled

    - Example message:

        - Subject: [Keg App] Password Reset Link
        - Body: Somebody asked to reset your password on Keg Application. If this was not you...

.. _gs-extension:

Extension Setup
---------------

-  Set up an auth manager (in app setup or extensions)
-  The entity registry hooks up user, group, bundle, and permission entities. You will need to
   create a registry to associate with the auth manager, and register your entities from the
   model (see model notes)
-  Note that the mail_manager is optional. If a mail_manager is not given, no mail will be sent
-  Permissions may be passed as simple string tokens, or as tuples of `(token, description)`

  - Note, the ``auth_manage`` permission is not assumed to be present, and must be specified
    to be preserved during sync.

.. code-block:: python

    from flask_mail import Mail
    from keg_auth import AuthManager, AuthMailManager, AuthEntityRegistry

    mail_ext = Mail()
    auth_mail_manager = AuthMailManager(mail_ext)
    auth_entity_registry = AuthEntityRegistry()

    _endpoints = {'after-login': 'public.home'}
    permissions = (
        ('auth-manage', 'manage users, groups, bundles, and view permissions'),
        ('app-permission1', 'access view Foo'),
        ('app-permission2', 'access the Bar area'),
    )

    auth_manager = AuthManager(mail_manager=auth_mail_manager, endpoints=_endpoints,
                                entity_registry=auth_entity_registry, permissions=permissions)
    auth_manager.init_app(app)
..


.. _gs-authenticators:

Login Authenticators
--------------------

Login Authenticators control validation of users.

- Includes logic for verifying a user from a login route, and other view-layer operations
  needed for user workflow (e.g. verifying email, password resets, etc.)
- Authenticator may be specified on the auth_manager:

    -  'KegAuthenticator' is the default primary authenticator, and uses username/password
    -  ``AuthManager(mail_ext, login_authenticator=LdapAuthenticator)``

- LDAP authentication

    - ``from keg_auth import LdapAuthenticator``
    - Uses python-ldap, which needs to be installed: ``pip install keg-auth[ldap]``
    - Additional config:

        - ``KEGAUTH_LDAP_TEST_MODE``: When True, bypasses LDAP calls. Defaults to False
        - ``KEGAUTH_LDAP_SERVER_URL``: Target LDAP server or list of servers to use for queries.
          If a list is given, authentication is attempted on each server in the given order
          until a successful query is made.
        - ``KEGAUTH_LDAP_DN_FORMAT``: Format-able string to set up for the query

            - ex. ``uid={},dc=example,dc=org``

- OAuth/OIDC authentication

    - ``from keg_auth import OidcAuthenticator``
    - Uses flask-oidc, which needs to be installed: ``pip install keg-auth[oidc]``
    - Additional config:

        - ``OIDC_PROVIDER_URL``: Target service location.
        - ``OIDC_CLIENT_ID``: OAuth ID for the app in the target service.
        - ``OIDC_CLIENT_SECRET``: Authenticating secret for app in the target service.
        - ``OIDC_AUTH_URI``: OAuth authorize URI. Default "/oauth2/v1/authorize".
        - ``OIDC_TOKEN_URI``: OAuth token URI. Default "/oauth2/v1/token".
        - ``OIDC_ISSUER``: OAuth issuer location. Default "/oauth2".
        - ``OIDC_USERINFO_URI``: OAuth user info URI. Default "/oauth2/userinfo".
        - ``KEGAUTH_OIDC_LOGOUT_REDIRECT``: Logout should bypass OAuth logout and just redirect
          to this URL. Default None.


.. _gs-loaders:

Request Loaders
---------------

Request Loaders run when a user is not in session. Each loader will look for identifying
data in the request, such as an authentication header.

-  ``AuthManager(mail_ext, request_loaders=JwtRequestLoader)``
-  Token authenticators, like JwtRequestLoader, have a `create_access_token` method

    -  ``token = auth_manager.get_request_loader('jwt').create_access_token(user)``

-  JWT:

    -  ``from keg_auth import JwtRequestLoader``
    -  uses flask-jwt-extended, which needs to be installed: ``pip install keg-auth[jwt]``

.. _gs-blueprint:

Blueprints
----------

Include an auth blueprint along with your app’s blueprints, which includes the login views
and user/group/bundle management. Requires AuthManager instance:

.. code-block:: python

    from keg_auth import make_blueprint
    from my_app.extensions import auth_manager
    auth_bp = make_blueprint(__name__, auth_manager)
..

.. _gs-cli:

CLI
---

An auth group is provided and set up on the app during extension init. You can extend
the group by using the cli_group attribute on the app's auth_manager, but you need access to the
app during startup to do that. You can use an event signal to handle this - just be sure
your app's `visit_modules` has the location of the event.

.. code-block:: python

    # in app definition
    visit_modules = ['.events']


    # in events module
    from keg.signals import init_complete

    from my_app.cli import auth_cli_extensions


    @init_complete.connect
    def init_app_cli(app):
        auth_cli_extensions(app)


    # in cli
    def auth_cli_extensions(app):
        @app.auth_manager.cli_group.command('command-extension')
        def command_extension():
            pass
..

Built-in commands:

-  ``create-user``: Create a user record and (depending on config) send a verify email.

  - Mail can be turned off with the `--no-mail` option
  - Create a superuser with the `--as-superuser` option
  - By default, has one required argument (email). If you wish to have
    additional arguments, put the list of arg names in `KEGAUTH_CLI_USER_ARGS` config

- ``set-password``: Allows you to set/reset the password for a given username.
- ``purge-attempts``: Reset login attempts on a user to clear blocking.


.. _gs-model:

Model
-----

Create entities using the existing mixins, and register them with keg_auth.
-  Note: the User model assumes that the entity mixed with UserMixin will have a PK id
-  Email address and token verification by email are in `UserEmailMixin`

    - i.e. if your app will not use email token verification for passwords, leave that mixin out

.. code-block:: python

    from keg.db import db
    from keg_elements.db.mixins import DefaultColsMixin, MethodsMixin
    from keg_auth import UserMixin, UserEmailMixin, PermissionMixin, BundleMixin, GroupMixin

    from my_app.extensions import auth_entity_registry


    class EntityMixin(DefaultColsMixin, MethodsMixin):
        pass


    @auth_entity_registry.register_user
    class User(db.Model, UserEmailMixin, UserMixin, EntityMixin):
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
..


Migrations
^^^^^^^^^^

Keg-Auth does not provide any model migrations out of the box. We want to be very flexible
with regard to the type of auth model in the app, so migrations become the app developer's
responsibility.

If you are using a migration library like ``alembic``, you can autogenerate a migration
after upgrading Keg-Auth to ensure any model updates from mixins are included.

.. _gs-navigation:

Navigation Helpers
------------------

Keg-Auth provides navigation helpers to set up a menu tree, for which nodes on the tree are
restricted according to the authentication/authorization requirements of the target endpoint.

Note: requirements are any class-level permission requirements. If authorization is defined
by an instance-level ``check_auth`` method, that will not be used by the navigation helpers.

-  Usage involves setting up a menu structure with NavItem/NavURL objects. Note that permissions on
   a route may be overridden for navigation purposes
-  Menus may be tracked on the auth manager, which will reset their cached access on
   login/logout
-  ``keg_auth/navigation.html`` template has a helper ``render_menu`` to render a given menu as a ul

    -  ``{% import "keg_auth/navigation.html" as navigation %}``
    -  ``render_menu(auth_manager.menus['main'])``
    -  ``render_menu(auth_manager.menus['main'], expand_to_current=True)``

    - Automatically expand/collapse menu groups for the currently-viewed item. Useful for vertical menus.

-  Collapsible groups can be added to navigation menus by nesting NavItems in the menu. The group item
   will get a ``nav_group`` attribute, which can be referred to in CSS.

    -  ``NavItem('Auth Menu', NavItem(...))`` will have a ``nav_group`` of ``#navgroup-auth-menu``
    -  ``NavItem('Auth Menu', NavItem(...), nav_group='foo')`` will have a ``nav_group`` of ``#navgroup-foo``

-  NavItems can specify an icon to display in the menu item by passing an ``icon_class`` string to the
   NavItem constructor. e.g., ``NavItem('Title', NavURL(...), icon_class='fas fa-shopping-cart')``.

Example:

.. code-block:: python

    from keg.signals import init_complete

    from keg_auth import NavItem, NavURL

    @init_complete.connect
    def init_navigation(app):
        app.auth_manager.add_navigation_menu(
            'main',
            NavItem(
                NavItem('Home', NavURL('public.home')),
                NavItem(
                    'Nesting',
                    NavItem('Secret1', NavURL('private.secret1')),
                    NavItem('Secret1 Class', NavURL('private.secret1-class')),
                ),
                NavItem('Permissions On Stock Methods', NavURL('private.secret2')),
                NavItem('Permissions On Methods', NavURL('private.someroute')),
                NavItem('Permissions On Class And Method', NavURL('private.secret4')),
                NavItem('Permissions On NavURL',
                    NavURL(
                        'private.secret3', requires_permissions='permission3'
                    )),
                NavItem('User Manage', NavURL('auth.user:add')),
            )
        )
..


.. _gs-templates:

Templates
---------

Templates are provided for the auth views, as well as base crud templates.

Base templates are referenced from settings. The first of these defined is used:

    -  `BASE_TEMPLATE`
    -  `KEGAUTH_BASE_TEMPLATE`

Form selects are rendered with select2 in templates extending ``keg_auth/form-base.html``.
``keg_auth/select2-scripts.html`` and ``keg_auth/select2-styles.html`` can be included
in templates to render select2s without extending form-base. Apps can opt out of select2
rendering with ``KEGAUTH_USE_SELECT2`` config.


.. _gs-views:

Views
-----

-  Views may be restricted for access using the requires\* decorators
-  Each decorator can be used as a class decorator or on individual
   view methods
-  Additionally, the decorator may be used on a Blueprint to apply the requirement to all
   routes on the blueprint
-  ``requires_user``

    -  Require a user to be authenticated before proceeding
       (authentication only)
    -  Usage: ``@requires_user`` or ``@requires_user()`` (both usage
       patterns are identical if no secondary authenticators are needed)
    -  Note: this is similar to ``flask_login.login_required``, but
       can be used as a class/blueprint decorator
    -  You may pass a custom `on_authentication_failure` callable to the decorator, else it will
       redirect to the login page
    -  A decorated class/blueprint may have a custom `on_authentication_failure` instance method instead
       of passing one to the decorator
    -  ``KEGAUTH_HTTP_METHODS_EXCLUDED`` can be overridden at the individual decorator level by passing
       ``http_methods_excluded`` to the decorator's constructor

-  ``requires_permissions``

    -  Require a user to be conditionally authorized before proceeding
       (authentication + authorization)
    -  ``has_any`` and ``has_all`` helpers can be used to construct
       complex conditions, using string permission tokens, nested
       helpers, and callable methods
    -  You may pass a custom `on_authorization_failure` callable to the decorator, else it will
       respond 403 Unauthorized
    -  A decorated class/blueprint may have a custom `on_authorization_failure` instance method instead
       of passing one to the decorator
    -  Usage:

        -  ``@requires_permissions(('token1', 'token2'))``
        -  ``@requires_permissions(has_any('token1', 'token2'))``
        -  ``@requires_permissions(has_all('token1', 'token2'))``
        -  ``@requires_permissions(has_all(has_any('token1', 'token2'), 'token3'))``
        -  ``@requires_permissions(custom_authorization_callable that takes user arg)``

-  A standard CRUD view is provided which has add, edit, delete, and list "actions"

    - ``from keg_auth import CrudView``
    - Because the standard action routes are predefined, you can assign specific permission(s) to
      them in the view's `permissions` dictionary, keyed by action (e.g. `permissions['add'] = 'foo'`)


.. _gs-global-hooks:

Global Request Hooks
--------------------

The authorization decorators will likely normally be used against view methods/classes and
blueprints. However, another scenario for usage would be request hooks. For example, if
authorization needs to be run across the board for any request, we can register a callback
on that hook, and apply the decorator accordingly.

.. code-block:: python

    from keg.signals import app_ready

    @app_ready.connect
    def register_request_started_handler(app):
        from keg_auth.libs.decorators import requires_permissions

        @app.before_request
        @requires_permissions(lambda user: user.is_qualified)
        def request_started_handler(*args, **kwargs):
            # Nothing special needs to happen here - the decorator does it all
            pass
..


.. _gs-limiting:

Attempt Limiting
----------------

Login and password reset attempts can be limited by registering an Attempt entity.
The Attempt entity must be a subclass of `AttemptMixin`.

Login attempts are limited by counting failed attempts. A successful login attempt will
reset the limit counter. Reset attempts are limited by counting all password reset attempts.

Attempt limiting can be configured with the following options:

-  ``KEGAUTH_LOGIN_ATTEMPT_LIMIT``
-  ``KEGAUTH_LOGIN_ATTEMPT_TIMESPAN``
-  ``KEGAUTH_LOGIN_ATTEMPT_LOCKOUT``
-  ``KEGAUTH_RESET_ATTEMPT_LIMIT``
-  ``KEGAUTH_RESET_ATTEMPT_TIMESPAN``
-  ``KEGAUTH_RESET_ATTEMPT_LOCKOUT``

For each of these options:

- Limit: maximum number of attempts within the timespan.
- Timespan: timespan in seconds in which the limit can be reached.
- Lockout: timespan in seconds until a successful attempt can be made after the limit is reached.

CLI `purge-attempts` will delete attempts for a given username. Optionally accepts `--attempt-type`
argument to only delete attempts of a certain type.


.. _gs-testing:

Testing and User Login
----------------------

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
            user = ents.User.testing_create(permissions=('permission1', 'permission2'))
            client = AuthTestApp(flask.current_app)

            resp = client.get('/secret-page', status=200, user=user)
            assert resp.text == 'secret-page'

            # User should only stick around for a single request (and will get a 302 redirect to the)
            # login view.
            client.get('/secret-page', status=302)

A helper class is also provided to set up a client and user, given the
permissions specified on the class definition:

.. code-block:: python

    from keg_auth.testing import ViewTestBase

    class TestMyView(ViewTestBase):
        permissions = 'permission1', 'permission2', ...

        def test_get(self):
            self.client.get('/foo')


.. _gs-nomail:

Using Without Email Functions
-----------------------------

Keg Auth is designed out of the box to use emailed tokens to:

- verify the email addresses on user records
- provide a method of initially setting passwords without the admin setting a known password

While this provides good security in many scenarios, there may be times when the email methods
are not desired (for example, if an app will run in an environment where the internet is not
accessible). Only a few changes are necessary from the examples above to achieve this:

- leave `UserEmailMixin` out of the `User` model
- do not specify a mail_manager when setting up `AuthManager`



.. _gs-passwordreset:

Email/Reset Password Functionality
------------------------------------

* The JWT tokens in the email / reset password emails are salted with
    * username/email (depends on which is enabled)
    * password hash
    * last login utc
    * is_active (verified/enabled combination)

    This allows for tokens to become invalidate anytime of the following happens:
        * username/email changes
        * password hash changes
        * a user logs in (last login utc will be updated and invalidate the token)
        * is active (depending on the model this is calculated from is_enabled/is_verified fields)

.. _gs-i18n:

Internationalization
--------------------

Keg-Auth supports `Babel`-style internationalization of text strings through the `morphi` library.
To use this feature, specify the extra requirements on install::

    pip install keg-auth[i18n]

Currently, English (default) and Spanish are the supported languages in the UI.

Helpful links
^^^^^^^^^^^^^

 * https://www.gnu.org/software/gettext/manual/html_node/Mark-Keywords.html
 * https://www.gnu.org/software/gettext/manual/html_node/Preparing-Strings.html


Message management
^^^^^^^^^^^^^^^^^^

The ``setup.cfg`` file is configured to handle the standard message extraction commands. For ease of development
and ensuring that all marked strings have translations, a tox environment is defined for testing i18n. This will
run commands to update and compile the catalogs, and specify any strings which need to be added.

The desired workflow here is to run tox, update strings in the PO files as necessary, run tox again
(until it passes), and then commit the changes to the catalog files.

.. code::

    tox -e i18n
