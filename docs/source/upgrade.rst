Upgrading Keg-Auth
==================

While we attempt to preserve backward compatibility, some KegAuth versions do introduce
breaking changes. This list should provide information on needed app changes.

- 0.6.0
  - OIDC authenticator (deprecated) has been removed. Use OAuth with configured profiles instead.
  - Model ``testing_create`` renamed to ``fake`` (follows KegElements 0.8.0)

  - Template files now follow keg's more recent naming scheme to use dashes instead of underscores.
    E.g. ``keg_auth/crud-list.html`` became ``keg-auth/crud-list.html``

  - ``keg-elements/form-view.html`` and ``keg-elements/grid-view.html`` are now available, so
    are used as bases for CRUD templates. ``form-base.html`` has been removed.

  - KegElements now handles Select2 css/js inclusion in its ``form-view.html`` template. That has
    been removed from KegAuth.
