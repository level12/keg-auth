from __future__ import absolute_import

from flask_mail import Mail
try:
    from flask_bootstrap import Bootstrap
except ImportError:
    Bootstrap = None
from flask_wtf.csrf import CSRFProtect
from keg.app import Keg
from kegauth import AuthManager

from kegauth_ta.views import blueprints

csrf = CSRFProtect()

_endpoints = {'after-login': 'public.home'}
mail_ext = Mail()
auth_manager = AuthManager(mail_ext, endpoints=_endpoints)


class KegAuthTestApp(Keg):
    import_name = 'kegauth_ta'
    db_enabled = True
    use_blueprints = blueprints
    keyring_enable = False

    def init(self, *args, **kwargs):
        super(KegAuthTestApp, self).init(*args, **kwargs)

        auth_manager.init_app(self)
        csrf.init_app(self)
        mail_ext.init_app(self)

        if Bootstrap is not None:
            Bootstrap(self)

        return self


if __name__ == '__main__':
    KegAuthTestApp.cli_run()
