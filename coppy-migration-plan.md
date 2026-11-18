# Coppy migration plan

Modernize Keg Auth with `../coppy`, then add GitHub Actions publishing.


## Scope

- Adopt Hatch, uv, Nox, and a `src/` layout; retain Copier answers for future updates.
- Preserve optional extras, the test application, Babel tooling, templates, and
  translation assets.
- Run tests on Python 3.12–3.14; use Python 3.14 for development tooling.
- Use PostgreSQL 15 for all test images, including Compose and GitHub Actions.
- Preserve PostgreSQL driver, stable-dependency, i18n, and documentation checks.
- Remove internal package-index references from configuration, documentation, and
  dependency sources; revisit the associated `python-ldap` pin.
- Include `sqlalchemy-pyodbc-mssql` in the stack modernization and dependency refresh: its
  SQLAlchemy/pyodbc fixes remain necessary. Determine dependency placement without
  automatically making it mandatory for Keg Auth.
- Validate wheel and sdist metadata, installation outside the checkout, and packaged
  templates and translations.
- Replace CircleCI with GitHub Actions and add tag-triggered PyPI trusted publishing of
  validated build artifacts.


## Sequence

1. Generate a temporary reference project from `../coppy` and integrate the template.
2. Complete packaging, dependency, and CI migration; verify builds and tests on Python
   3.12–3.14 with PostgreSQL 15.
3. Add publishing in a follow-up PR and configure the matching PyPI trusted publisher and
   GitHub environment.


## References

- [Pals #54: Coppy migration](https://github.com/level12/pals/pull/54)
- [Pals #57: publishing workflow](https://github.com/level12/pals/pull/57)
- [Keg Storage #92: library modernization](https://github.com/level12/keg-storage/pull/92)
