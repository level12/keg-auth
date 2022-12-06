Keg Auth’s Readme
==========================================

.. image:: https://circleci.com/gh/level12/keg-auth.svg?&style=shield&circle-token=b90c5336d179f28df73d404a26924bc373840257
    :target: https://circleci.com/gh/level12/keg-auth

.. image:: https://codecov.io/github/level12/keg-auth/coverage.svg?branch=master&token=hl15MQRPeF
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

To run this project's tests:

- Copy keg_auth_ta-config-example.py -> keg_auth_ta-config.py, update as needed
- Override database addr &/or port with environment vars or docker compose override if needed.
- `docker-compose up [-d]`
- `tox ...`

There is a test application defined that can be ran like:

- `cd keg_auth_ta`
- `python app.py ...`
