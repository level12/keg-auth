Changelog
=========

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

