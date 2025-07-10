Changelog
=========

0.8.1 released 2025-07-10
-------------------------

- resolve type comparison for fetching user by ID (bfff353_)

.. _bfff353: https://github.com/level12/keg-auth/commit/bfff353


0.8.0 released 2024-06-28
-------------------------

- support python 3.12 (66a3706_)
- move passlib.pwd usage to utils methods due to deprecation warnings (6bc20ab_)

.. _66a3706: https://github.com/level12/keg-auth/commit/66a3706
.. _6bc20ab: https://github.com/level12/keg-auth/commit/6bc20ab


0.7.3 released 2023-10-17
-------------------------

- use oauth authenticator class passed to auth manager (b6feae6_)
- trap permissions error emitted by sqlite db on sync (ba0d3b2_)

.. _b6feae6: https://github.com/level12/keg-auth/commit/b6feae6
.. _ba0d3b2: https://github.com/level12/keg-auth/commit/ba0d3b2


0.7.2 released 2023-05-22
-------------------------

- handle multiple potential session cookies resulting from werkzeug 2.3 and flask 2.3 changes (8b4680e_)

.. _8b4680e: https://github.com/level12/keg-auth/commit/8b4680e


0.7.1 released 2023-05-12
-------------------------

- allow request loaders to be specified directly to requires decorators (cd42358_)

.. _cd42358: https://github.com/level12/keg-auth/commit/cd42358


0.7.0 released 2023-03-03
-------------------------

- support SQLAlchemy 2.0 (88a6173_)
- support keg testing app context changes (d0ec64f_)

.. _88a6173: https://github.com/level12/keg-auth/commit/88a6173
.. _d0ec64f: https://github.com/level12/keg-auth/commit/d0ec64f


0.6.2 released 2022-12-20
-------------------------

- trap the unknown hash error to prevent invalid password data from causing app errors refs #160 (5f2b721_)

.. _5f2b721: https://github.com/level12/keg-auth/commit/5f2b721


0.6.1 released 2022-12-15
-------------------------

- support multiple db sessions when running auth tests (a5cab4a_)
- fixed upgrade notes in documentation (b537bba_)

.. _a5cab4a: https://github.com/level12/keg-auth/commit/a5cab4a
.. _b537bba: https://github.com/level12/keg-auth/commit/b537bba


0.6.0 released 2022-12-12
-------------------------

- update documentation of breaking changes (1ebb337_)
- **BC break** support keg-elements 0.8.0 (6d4b251_)
- log attempts when form validation fails, and when csrf doesn't validate (60edacb_)
- resolve field order error when disabled_utc missing from user form fields (0e2ae74_)
- document known data migration issue (23ec6fe_)
- pin python-ldap to version in package index (0b1d2b7_)
- apply workaround to support testing with flask-login 0.6.2 (d1446a9_)
- drop deprecated OIDC code and any remaining python 2 references (10b1144_)

.. _1ebb337: https://github.com/level12/keg-auth/commit/1ebb337
.. _6d4b251: https://github.com/level12/keg-auth/commit/6d4b251
.. _60edacb: https://github.com/level12/keg-auth/commit/60edacb
.. _0e2ae74: https://github.com/level12/keg-auth/commit/0e2ae74
.. _23ec6fe: https://github.com/level12/keg-auth/commit/23ec6fe
.. _0b1d2b7: https://github.com/level12/keg-auth/commit/0b1d2b7
.. _d1446a9: https://github.com/level12/keg-auth/commit/d1446a9
.. _10b1144: https://github.com/level12/keg-auth/commit/10b1144


0.5.7 released 2022-08-12
-------------------------

- prevent attempt tests from failing when certain config values are set in app (b2f7e27_)

.. _b2f7e27: https://github.com/level12/keg-auth/commit/b2f7e27


0.5.6 released 2022-08-12
-------------------------

- skip attempt tests during execution to avoid import order issues (8ea6f57_)

.. _8ea6f57: https://github.com/level12/keg-auth/commit/8ea6f57


0.5.5 released 2022-08-10
-------------------------

- flash on login for users disabled by date, autoclear disabled date when re-enabling (9330f62_)

.. _9330f62: https://github.com/level12/keg-auth/commit/9330f62


0.5.4 released 2022-07-08
-------------------------

- case insensitive match on user id (d01c310_)
- use relative URLs in tests (6d6f959_)

.. _d01c310: https://github.com/level12/keg-auth/commit/d01c310
.. _6d6f959: https://github.com/level12/keg-auth/commit/6d6f959


0.5.3 released 2022-02-24
-------------------------

- fix integrated auth tests (4318826_)

.. _4318826: https://github.com/level12/keg-auth/commit/4318826


0.5.2 released 2022-02-24
-------------------------

- add OAuth authenticator to replace deprecated OIDC implementation (606c952_)
- add basic user/group/bundle CRUD tests to the integrated auth tests (0c84a2d_)
- *BC break* require rate-limiting setup by default, simplify configuration (7d7b532_)

.. _606c952: https://github.com/level12/keg-auth/commit/606c952
.. _0c84a2d: https://github.com/level12/keg-auth/commit/0c84a2d
.. _7d7b532: https://github.com/level12/keg-auth/commit/7d7b532


0.5.1 released 2022-02-22
-------------------------

- warn on usage of OIDC authenticator due to current breakage in flask-oidc (c582781_)
- *potential BC break* use keg-elements field ordering scheme on the User form (ee31b79_)
- add class and code options to NavItems for better control of rendering (2842cc2_)
- clear flask session on logout, behavior can be turned off via config setting (71e6b10_)
- stop overriding a title block in templates, use config value to set the proper variable for the app template (210f227_)
- load orm entity in CRUD method (89bc7d4_)

.. _c582781: https://github.com/level12/keg-auth/commit/c582781
.. _ee31b79: https://github.com/level12/keg-auth/commit/ee31b79
.. _2842cc2: https://github.com/level12/keg-auth/commit/2842cc2
.. _71e6b10: https://github.com/level12/keg-auth/commit/71e6b10
.. _210f227: https://github.com/level12/keg-auth/commit/210f227
.. _89bc7d4: https://github.com/level12/keg-auth/commit/89bc7d4


0.5.0 released 2022-02-21
-------------------------

- use the Bootstrap 4 base form template from keg-elements (16c393a_)
- shift to authlib for verification token generate/verify - support generated itsdangerous tokens for now refs #147 (e96ac2e_)

.. _16c393a: https://github.com/level12/keg-auth/commit/16c393a
.. _e96ac2e: https://github.com/level12/keg-auth/commit/e96ac2e


0.4.2 released 2022-01-20
-------------------------

- replace commonmark with markdown-it-py (8b4822d_)

.. _8b4822d: https://github.com/level12/keg-auth/commit/8b4822d


0.4.1 released 2021-11-29
-------------------------

- fix navigation use of callable permissions on classes/blueprints (f19f513_)
- user form: don't assume csrf_token field exists (07fe642_)
- improve testing developer ux (b687c72_)

.. _f19f513: https://github.com/level12/keg-auth/commit/f19f513
.. _07fe642: https://github.com/level12/keg-auth/commit/07fe642
.. _b687c72: https://github.com/level12/keg-auth/commit/b687c72


0.4.0 released 2021-09-13
-------------------------

- ensure grid header posts are supported (e0638dc_)
- shift to use Bootstrap 4 templates by default (39335bc_)
- centralize validation of permission sets in testing (9f04f1d_)
- ViewTestBase no longer delete users in setup, and provide hooks into user creation (7d72fc3_)
- enhance navigation menu options for login/logout cases (667a1ac_)
- rename package for proper semantics (6a6a202_)

.. _e0638dc: https://github.com/level12/keg-auth/commit/e0638dc
.. _39335bc: https://github.com/level12/keg-auth/commit/39335bc
.. _9f04f1d: https://github.com/level12/keg-auth/commit/9f04f1d
.. _7d72fc3: https://github.com/level12/keg-auth/commit/7d72fc3
.. _667a1ac: https://github.com/level12/keg-auth/commit/667a1ac
.. _6a6a202: https://github.com/level12/keg-auth/commit/6a6a202


0.3.0 released 2021-07-06
-------------------------

- click changed output for hidden inputs, resolve for set-password CLI (6cd5a09_)
- update python requirements and pip usage (760da0b_)
- add options to exclude specific HTTP methods from auth checks (b66d090_)
- update JWT usage to reflect flask-jwt-extended 4.0 breaking changes (1cd0895_)
- switch ldap requirement to python-ldap (63485f3_)

.. _6cd5a09: https://github.com/level12/keg-auth/commit/6cd5a09
.. _760da0b: https://github.com/level12/keg-auth/commit/760da0b
.. _b66d090: https://github.com/level12/keg-auth/commit/b66d090
.. _1cd0895: https://github.com/level12/keg-auth/commit/1cd0895
.. _63485f3: https://github.com/level12/keg-auth/commit/63485f3


0.2.28 released 2021-04-20
--------------------------

- support args in http head requests (97f8961_)
- pin flask-jwt-extended < 4 until we support the update

.. _97f8961: https://github.com/level12/keg-auth/commit/97f8961


0.2.27 released 2021-02-02
--------------------------

- fix documentation of internationalization support (8a41f03_)
- make form/crud templates less opinionated about how base templates render page title (0b71303_)

.. _8a41f03: https://github.com/level12/keg-auth/commit/8a41f03
.. _0b71303: https://github.com/level12/keg-auth/commit/0b71303


0.2.26 released 2021-01-29
--------------------------

- Provide Spinx documentation (62aca54_)
- Provide a default JS handler for confirm-delete in crud-list (7b6785a_)
- Use marksafe and jinja templates instead of webhelpers2 (8f68e07_)
- Allow user to prevent sending welcome email after user form (3bb8f7a_)
- Validate that create_form returned a value (83ff034_)
- Trap integrity error on permission sync to mitigate race condition (4d7497c_)
- Move disabled_utc to be with the other fields (dd1bf5e_)

.. _62aca54: https://github.com/level12/keg-auth/commit/62aca54
.. _7b6785a: https://github.com/level12/keg-auth/commit/7b6785a
.. _8f68e07: https://github.com/level12/keg-auth/commit/8f68e07
.. _3bb8f7a: https://github.com/level12/keg-auth/commit/3bb8f7a
.. _83ff034: https://github.com/level12/keg-auth/commit/83ff034
.. _4d7497c: https://github.com/level12/keg-auth/commit/4d7497c
.. _dd1bf5e: https://github.com/level12/keg-auth/commit/dd1bf5e


0.2.25 released 2020-12-08
--------------------------

- CRUD view passes through args set with self.assign (efeb7b7_)
- CRUD view edit/delete performs authorization prior to ID lookup (efeb7b7_)
- CRUD view added webgrid render limit handling (efeb7b7_)

.. _efeb7b7: https://github.com/level12/keg-auth/commit/efeb7b7


0.2.24 released 2020-07-09
--------------------------

- Fix inconsistent CLI argument ordering in tests (d9a62c0_)

.. _d9a62c0: https://github.com/level12/keg-auth/commit/d9a62c0


0.2.23 released 2020-06-11
--------------------------

- Allow applications to enforce custom password policies (7111c20_)
- Check translations in CI (825d32e_)

.. _7111c20: https://github.com/level12/keg-auth/commit/7111c20
.. _825d32e: https://github.com/level12/keg-auth/commit/825d32e


0.2.22 released 2020-04-16
--------------------------

- Allow rate-limiting of login and password resets (d243b75_)
- Add more config flexibility for OIDC (39beae0_)

.. _d243b75: https://github.com/level12/keg-auth/commit/d243b75
.. _39beae0: https://github.com/level12/keg-auth/commit/39beae0


0.2.21 released 2020-04-02
--------------------------

- Resolve fuzzy/missing translations (a78de96_)
- Add inactivation date for users (requires migration to add a field) (0020fbd_)
- Support latest Flask-Login (ba59925_)
- Allow unverified users to reset their passwords (8888386_)
- Pin keg-elements requirement to support CRUD checkboxes (e59fcc1_)
- Include an Allow header for 405 responses (a2a3091_)
- Support multiple LDAP targets (b895aad_)
- Handle HEAD requests (b16a7e4_)
- Remove six dependency (477a415_)

.. _a78de96: https://github.com/level12/keg-auth/commit/a78de96
.. _0020fbd: https://github.com/level12/keg-auth/commit/0020fbd
.. _ba59925: https://github.com/level12/keg-auth/commit/ba59925
.. _8888386: https://github.com/level12/keg-auth/commit/8888386
.. _e59fcc1: https://github.com/level12/keg-auth/commit/e59fcc1
.. _a2a3091: https://github.com/level12/keg-auth/commit/a2a3091
.. _b895aad: https://github.com/level12/keg-auth/commit/b895aad
.. _b16a7e4: https://github.com/level12/keg-auth/commit/b16a7e4
.. _477a415: https://github.com/level12/keg-auth/commit/477a415


0.2.20 released 2020-03-24
--------------------------

- OIDC and related updates (fab68f5_)
- Add OIDC authenticator and login/logout view responders
- Fix missing page header for Permissions view
- Allow passing blueprint kwargs to make_blueprint
- Easier disabling of specific auth views
- Allow view responder flash messages to be disabled
- Drop bulk permission controls (better templating now in keg-elements)

.. _fab68f5: https://github.com/level12/keg-auth/commit/fab68f5


0.2.19 released 2020-02-21
--------------------------

- Improve Usability of Permission Dropdown (479e985_)
- Pin Flask Login (00ea957_)

.. _479e985: https://github.com/level12/keg-auth/commit/479e985
.. _00ea957: https://github.com/level12/keg-auth/commit/00ea957


0.2.18 released 2020-01-10
--------------------------

- add CLI command for dev to set password (d488bc9_)

.. _d488bc9: https://github.com/level12/keg-auth/commit/d488bc9


0.2.17 released 2019-12-12
--------------------------

- ensure token is present for resending verification email (01b566f_)

.. _01b566f: https://github.com/level12/keg-auth/commit/01b566f


0.2.16 released 2019-12-02
--------------------------

- fix CRUD edit form default values for relationships (01893f9_)

.. _01893f9: https://github.com/level12/keg-auth/commit/01893f9


0.2.15 released 2019-11-27
--------------------------

- fix bundle grid setup for CRUD view (b772f01_)

.. _b772f01: https://github.com/level12/keg-auth/commit/b772f01


0.2.14 released 2019-11-21
--------------------------

- fix template issue related to select2 updates (373739b_)
- make auth testing helpers more generic (b90ee96_)

.. _373739b: https://github.com/level12/keg-auth/commit/373739b
.. _b90ee96: https://github.com/level12/keg-auth/commit/b90ee96


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

