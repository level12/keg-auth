from __future__ import absolute_import

from flask_wtf.csrf import CSRFProtect
from keg.app import Keg
from kegauth import AuthManager

from kegauth_ta.views import blueprints

csrf = CSRFProtect()

_endpoints = {'after-login': 'public.home'}
auth_manager = AuthManager(endpoints=_endpoints)


class KegAuthTestApp(Keg):
    import_name = 'kegauth_ta'
    db_enabled = True
    use_blueprints = blueprints
    keyring_enable = False

    def init(self, *args, **kwargs):
        super(KegAuthTestApp, self).init(*args, **kwargs)

        auth_manager.init_app(self)
        csrf.init_app(self)

        return self


if __name__ == '__main__':
    KegAuthTestApp.cli_run()
