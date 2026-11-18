Keg Auth’s Readme
==========================================

.. image:: https://github.com/level12/keg-auth/actions/workflows/nox.yaml/badge.svg
    :target: https://github.com/level12/keg-auth/actions/workflows/nox.yaml

.. image:: https://codecov.io/github/level12/keg-auth/coverage.svg?branch=master
    :target: https://codecov.io/github/level12/keg-auth?branch=master

Flask extension in the Keg ecosystem to wrap authentication and authorization functionality. Keg-Auth
provides helpers for auth model, view/authorization setup, protected navigation menus, and more.


Installation
------------

- Bare functionality: `pip install keg-auth`
- With mail (i.e. with a mail manager configured, see below): `pip install keg-auth[mail]`
- JWT (for using JWT tokens as authenticators): `pip install keg-auth[jwt]`
- LDAP (for using LDAP target for authentication): `pip install keg-auth[ldap]`
- OAuth (e.g. Google Auth): `pip install keg-auth[oauth]`
- Internationalization extensions: `pip install keg-auth[i18n]`


A Simple Example
----------------

For a simple example and a checklist of sorts for app setup, see the
`Getting Started guide <https://keg-auth.readthedocs.io/en/stable/getting-started.html>`_ in the docs.


Demo
----

Typical usage is demonstrated in
https://github.com/level12/keg-app-cookiecutter


Links
-----

* Documentation: https://keg-auth.readthedocs.io/en/stable/index.html
* Releases: https://pypi.org/project/Keg-Auth/
* Code: https://github.com/level12/keg-auth
* Issue tracker: https://github.com/level12/keg-auth/issues
* Keg framework: https://github.com/level12/keg
* Questions & comments: http://groups.google.com/group/blazelibs


Development
-----------

Development uses Python 3.14, mise, and uv. Tests cover Python 3.12–3.14.
Install LDAP build prerequisites first (on Ubuntu: ``libldap2-dev libsasl2-dev``).

.. code:: shell

    mise trust
    mise bootstrap
    docker compose up -d
    mise exec -- nox

Compose uses PostgreSQL 15. Set ``KEG_AUTH_DB_IP`` and ``KEG_AUTH_DB_PORT`` for
both Compose and tests to override its address. For other application settings,
copy ``keg_auth_ta-config-example.py`` to ``keg_auth_ta-config.py`` and update it.

Run individual checks with ``mise exec -- nox -s pytest-3.14``,
``mise exec -- nox -s i18n``, ``mise exec -- nox -s docs``, or
``mise exec -- nox -s build``. The build check verifies wheel and sdist assets and
imports the installed wheel outside the checkout.

The test application can be run with ``mise exec -- python -m keg_auth_ta.app``.

After intentionally updating dependencies, refresh the stable test snapshot:

.. code:: shell

    uv export --frozen --no-default-groups --group pytest --no-emit-project \
        --no-hashes --no-header --no-annotate > stable-requirements.txt

Publishing
----------

GitHub Actions builds and validates distributions, then publishes them to PyPI
on a ``v*.*.*`` tag. Configure the existing PyPI project's trusted publisher
with owner ``level12``, repository ``keg-auth``, workflow ``pypi.yaml``, and
GitHub environment ``pypi`` before the first release.

``mise version show`` displays the version. ``mise version bump micro`` updates
the version, commits, creates a signed tag, and pushes by default; use
``--no-push`` to prepare a release locally. Use ``minor`` or ``major`` as needed
for the project's existing version scheme.
