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
- OAuth (e.g. Google Auth): `pip install keg-auth[oauth]`
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

- ``KEGAUTH_LOGOUT_CLEAR_SESSION``: Flag to clear flask session on logout. Default True
- ``KEGAUTH_CRUD_INCLUDE_TITLE``: Control whether form/grid CRUD templates render an h1 tag
- ``KEGAUTH_TEMPLATE_TITLE_VAR``: Template var to set for use in a base template's head -> title tag
- ``KEGAUTH_REDIRECT_LOGIN_TARGET``: If using the redirect authenticator (like for OAuth), set this to the target
- ``KEGAUTH_OAUTH_PROFILES``: Set of OAuth config, see section below
-  Email settings

    -  ``KEGAUTH_EMAIL_OPS_ENABLED``: Defaults to True if mail manager is given, controls all email ops
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

- OAuth authentication

    - ``from keg_auth import OAuthAuthenticator``
    - Uses additional dependencies: ``pip install keg-auth[oauth]``
    - Leans on ``authlib`` for the OAuth client

        - A number of client configurations may be found at https://github.com/authlib/loginpass

    - Additional config:

        - ``KEGAUTH_OAUTH_PROFILES``: list of OAuth provider profile dicts
        - Each profile should have the following keys:

            - ``domain_filter``: string or list of strings
            - ``id_field``: field in the resulting user info to use as the user identity
            - ``oauth_client_kwargs``: ``authlib`` client configuration. All of these args will be passed.

        - Multiple providers are supported. Login will be served at ``/login/<profile-name>``
        - If using a single provider and OAuth will be the only authenticator, consider mapping
          ``/login`` via the ``RedirectAuthenticator`` and setting ``KEGAUTH_REDIRECT_LOGIN_TARGET``.

    - Domain exclusions

        - If an OAuth profile is given a domain filter, only user identities within that domain will be
          allowed to login via that provider.
        - Filtered domains will be disallowed from password login, if ``KegAuthenticator`` is the primary.
        - Filtered domains will also prevent a user's domain from being changed in user admin.


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

__Note__: autogenerated migrations solve most of the problems, but if you are starting with
an existing database that already has user records, you may have some data issues to resolve
as well. The following are known issues:

- Email field is expected to have all lowercase data. The model type assumes that because email
addresses are not case-sensitive, it can coerce input to lowercase for comparison, and expects
that persisted data matches that assumption.

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

    -  ``{% import "keg-auth/navigation.html" as navigation %}``
    -  ``render_menu(auth_manager.menus['main'])``
    -  ``render_menu(auth_manager.menus['main'], expand_to_current=True)``

    - Automatically expand/collapse menu groups for the currently-viewed item. Useful for vertical menus.

-  Collapsible groups can be added to navigation menus by nesting NavItems in the menu. The group item
   will get a ``nav_group`` attribute, which can be referred to in CSS.

    -  ``NavItem('Auth Menu', NavItem(...))`` will have a ``nav_group`` of ``#navgroup-auth-menu``
    -  ``NavItem('Auth Menu', NavItem(...), nav_group='foo')`` will have a ``nav_group`` of ``#navgroup-foo``

-  NavItems can specify an icon to display in the menu item by passing an ``icon_class`` string to the
   NavItem constructor. e.g., ``NavItem('Title', NavURL(...), icon_class='fas fa-shopping-cart')``.

-  NavItems can be given a ``class_`` kwarg that will be applied to the whole ``li`` tag in the default
   render. This applies to both group items and the menu links themselves.

-  NavItems can also be provided a ``code`` kwarg, which is useful when doing custom templating to render
   the menu. The code is a code-only tag for the menu that can remain the same even if the menu wording
   changes. For example, the code could be used in a conditional template block to render certain menu
   items differently from the rest.

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
                    class_='my-nest-class',
                ),
                NavItem('Permissions On Stock Methods', NavURL('private.secret2')),
                NavItem('Permissions On Methods', NavURL('private.someroute')),
                NavItem('Permissions On Class And Method', NavURL('private.secret4')),
                NavItem('Permissions On NavURL',
                    NavURL(
                        'private.secret3', requires_permissions='permission3'
                    )),
                NavItem('User Manage', NavURL('auth.user:add')),
                NavItem('Logout', NavURL('auth.logout'), code='i-am-different'),
                NavItem('Login', NavURL('auth.login', requires_anonymous=True)),
            )
        )
..


.. _gs-templates:

Templates
---------

Templates are provided for the auth views, as well as base crud templates.

Base templates use keg-elements' form-view and grid-view parent templates. The app template to
extend is  referenced from settings. The first of these defined is used:

    -  `BASE_TEMPLATE`
    -  `KEG_BASE_TEMPLATE`

Keg-Auth will assume that a variable is used in the master template to determine the contents
of a title block. That variable name defaults to ``page_title``, but may be customized
via ``KEGAUTH_TEMPLATE_TITLE_VAR``.


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

Login, forgot password, and reset attempts are limited by registering an Attempt entity.
The Attempt entity must be a subclass of `AttemptMixin`.

Attempt limiting is enabled by default, which requires the entity. But, it may be disabled
in configuration.

Login attempts are limited by counting failed attempts. A successful login attempt will
reset the limit counter. Reset attempts are limited by counting all password reset attempts.

Attempt limiting can be configured with the following options:

-  ``KEGAUTH_ATTEMPT_LIMIT_ENABLED``: primary config switch, default True.
-  ``KEGAUTH_ATTEMPT_LIMIT``: maximum number of attempts within the timespan, default 15.
-  ``KEGAUTH_ATTEMPT_TIMESPAN``: timespan in seconds in which the limit can be reached, default 10 minutes.
-  ``KEGAUTH_ATTEMPT_LOCKOUT``: timespan in seconds until a successful attempt can be made after the limit is reached, default 1 hour.
-  ``KEGAUTH_ATTEMPT_IP_LIMIT``: base locking on IP address as well as input, default True.
-  ``KEGAUTH_LOGIN_ATTEMPT_LIMIT``: overrides KEGAUTH_ATTEMPT_LIMIT for the login view.
-  ``KEGAUTH_LOGIN_ATTEMPT_TIMESPAN``: overrides KEGAUTH_ATTEMPT_TIMESPAN for the login view.
-  ``KEGAUTH_LOGIN_ATTEMPT_LOCKOUT``: overrides KEGAUTH_ATTEMPT_LOCKOUT for the login view.
-  ``KEGAUTH_FORGOT_ATTEMPT_LIMIT``: overrides KEGAUTH_ATTEMPT_LIMIT for the forgot password view.
-  ``KEGAUTH_FORGOT_ATTEMPT_TIMESPAN``: overrides KEGAUTH_ATTEMPT_TIMESPAN for the forgot password view.
-  ``KEGAUTH_FORGOT_ATTEMPT_LOCKOUT``: overrides KEGAUTH_ATTEMPT_LOCKOUT for the forgot password view.
-  ``KEGAUTH_RESET_ATTEMPT_LIMIT``: overrides KEGAUTH_ATTEMPT_LIMIT for the reset password view.
-  ``KEGAUTH_RESET_ATTEMPT_TIMESPAN``: overrides KEGAUTH_ATTEMPT_TIMESPAN for the reset password view.
-  ``KEGAUTH_RESET_ATTEMPT_LOCKOUT``: overrides KEGAUTH_ATTEMPT_LOCKOUT for the reset password view.

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

        def setup_method(self):
            ents.User.delete_cascaded()

        def test_authenticated_client(self):
            """
                Demonstrate logging in at the client level.  The login will apply to all requests made
                by this client.
            """
            user = ents.User.fake()
            client = AuthTestApp(flask.current_app, user=user)
            resp = client.get('/secret2', status=200)
            assert resp.text == 'secret2'

        def test_authenticated_request(self):
            """
                Demonstrate logging in at the request level.  The login will only apply to one request.
            """
            user = ents.User.fake(permissions=('permission1', 'permission2'))
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
