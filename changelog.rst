Changelog
=========

0.2.13 released 2019-11-08
--------------------------

- use select2 to render selects on the user management views (30ff332_)
- fix breakage with keg 0.8.1 (3f5668d_)
- adjust CI environments to use (b9b4fb4_)
- auth test helpers use endpoints to find correct url (76a1222_)

.. _30ff332: https://github.com/level12/keg-auth/commit/30ff332
.. _3f5668d: https://github.com/level12/keg-auth/commit/3f5668d
.. _b9b4fb4: https://github.com/level12/keg-auth/commit/b9b4fb4
.. _76a1222: https://github.com/level12/keg-auth/commit/76a1222


0.2.12 released 2019-10-03
--------------------------

- support decorating flask class-based views (3d8a6cb_)
- fix LDAP authenticator for missing user case (19d184e_)

.. _3d8a6cb: https://github.com/level12/keg-auth/commit/3d8a6cb
.. _19d184e: https://github.com/level12/keg-auth/commit/19d184e


0.2.11 released 2019-09-27
--------------------------

- fix permission sync method and test hook (a56eda4_)
- fix FontAwesome usage on CRUD list view template (64f759a_)
- support lazy strings and icons in navigation helpers and templates (4473571_)
- remove flask version pin (ab47362_)

.. _a56eda4: https://github.com/level12/keg-auth/commit/a56eda4
.. _64f759a: https://github.com/level12/keg-auth/commit/64f759a
.. _4473571: https://github.com/level12/keg-auth/commit/4473571
.. _ab47362: https://github.com/level12/keg-auth/commit/ab47362


0.2.10 released 2019-09-18
--------------------------

- fix testing utils mock import to prevent needing mock dependency (da197df_)

.. _da197df: https://github.com/level12/keg-auth/commit/da197df


0.2.9 released 2019-07-27
-------------------------

- Provide a hook on the CRUD base class to allow overriding the default add url generation (#74) (7eea8bb_)

.. _7eea8bb: https://github.com/level12/keg-auth/commit/7eea8bb


0.2.8 released 2019-06-17
-------------------------

- resolve bug in testing permission existence check (feccb98_)

.. _feccb98: https://github.com/level12/keg-auth/commit/feccb98


0.2.7 released 2019-06-07
-------------------------

- make custom action access control easier (63921ee_)
- enforce test permissions are specified to the auth manager (794f320_)
- correct the MRO order in CRUD forms and testing models (2f4c451_)
- add get_current_user helper method (cae02a2_)
- make grid action column link CSS classes customizable (aa1bc21_)
- ensure CRUD view passes in desired template args (aae3dad_)

.. _63921ee: https://github.com/level12/keg-auth/commit/63921ee
.. _794f320: https://github.com/level12/keg-auth/commit/794f320
.. _2f4c451: https://github.com/level12/keg-auth/commit/2f4c451
.. _cae02a2: https://github.com/level12/keg-auth/commit/cae02a2
.. _aa1bc21: https://github.com/level12/keg-auth/commit/aa1bc21
.. _aae3dad: https://github.com/level12/keg-auth/commit/aae3dad


0.2.6 released 2019-02-12
-------------------------

- Merge pull request #60 from level12/move-sync-perms-to-entity (3181691_)
- update readme to remove reference to view-scoped authenticators (514c202_)

.. _3181691: https://github.com/level12/keg-auth/commit/3181691
.. _514c202: https://github.com/level12/keg-auth/commit/514c202


0.2.5 released 2018-11-14
-------------------------

- Allow make_blueprint to accept a custom blueprint class (fe635b2_)
- Add a link to resend verification email (f7a6191_)
- Add optional i18n support using morphi (790d3ab_)
- Fix intermittent test failure resulting from login timestamp (cde083b_)
- Refactor CRUD form/grid render to extract template args (34d4a20_)

.. _fe635b2: https://github.com/level12/keg-auth/commit/fe635b2
.. _f7a6191: https://github.com/level12/keg-auth/commit/f7a6191
.. _790d3ab: https://github.com/level12/keg-auth/commit/790d3ab
.. _cde083b: https://github.com/level12/keg-auth/commit/cde083b
.. _34d4a20: https://github.com/level12/keg-auth/commit/34d4a20


0.2.4
------------------

- Show verification URL on CLI even if mail flag is off

0.2.3
------------------

- Fix requires_user decorator for usage with blueprints

0.2.1
------------------

- Fix nav items to cache on per user basis
- Fix token generated in CLI having an unknown timezone applied

0.2.0
------------------

- Support permissions
- Decorate blueprints, classes, methods for user/permission requirements
- Support request loaders for tokens

0.1.0
------------------

- Initial release

