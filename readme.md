# Keg-Auth

[![nox](https://github.com/level12/keg-auth/actions/workflows/nox.yaml/badge.svg)](https://github.com/level12/keg-auth/actions/workflows/nox.yaml)
[![codecov](https://codecov.io/github/level12/keg-auth/coverage.svg?branch=master)](https://codecov.io/github/level12/keg-auth?branch=master)

Flask extension in the Keg ecosystem to wrap authentication and authorization
functionality. Keg-Auth provides helpers for auth model, view/authorization setup,
protected navigation menus, and more.


## Installation

- Bare functionality: `pip install keg-auth`
- With mail (i.e. with a mail manager configured): `pip install keg-auth[mail]`
- JWT (for using JWT tokens as authenticators): `pip install keg-auth[jwt]`
- LDAP (for using LDAP target for authentication): `pip install keg-auth[ldap]`
- OAuth (e.g. Google Auth): `pip install keg-auth[oauth]`
- Internationalization extensions: `pip install keg-auth[i18n]`


## A Simple Example

For a simple example and a checklist of sorts for app setup, see the
[Getting Started guide](https://keg-auth.readthedocs.io/en/stable/getting-started.html)
in the docs.


## Demo

Typical usage is demonstrated in
[keg-app-cookiecutter](https://github.com/level12/keg-app-cookiecutter).


## Links

- Documentation: <https://keg-auth.readthedocs.io/en/stable/index.html>
- Releases: <https://pypi.org/project/Keg-Auth/>
- Code: <https://github.com/level12/keg-auth>
- Issue tracker: <https://github.com/level12/keg-auth/issues>
- Keg framework: <https://github.com/level12/keg>
- Questions & comments: <http://groups.google.com/group/blazelibs>


## Dev


### Copier Template

Project structure and tooling mostly derives from
[Coppy](https://github.com/level12/coppy). See its documentation for context and
additional instructions.

This project can be updated from the upstream repo, see
[Updating a Project](https://github.com/level12/coppy?tab=readme-ov-file#template-updates).


### Project Setup

From zero to hero (passing tests that is):

1. Ensure [host dependencies](https://github.com/level12/coppy/wiki/Mise) are installed

2. Start docker service dependencies (if applicable):

   `docker compose up -d`

3. Sync [project](https://docs.astral.sh/uv/concepts/projects/) virtualenv w/ lock file:

   `uv sync`

4. Configure prek:

   `prek install`

5. Run tests:

   `nox`

Copy `keg_auth_ta-config-example.py` to `keg_auth_ta-config.py` and update as needed.
Override database addr &/or port with environment vars or docker compose override if
needed.

The test application can be run with `python -m keg_auth_ta.app`.


### Versions

A `version` task shows and bumps versions:

```shell

  # Show current version
  mise run version show

  # Bump version, tag, and push:
  mise run version bump

  # See other options
  mise run version -- --help
```
