from __future__ import absolute_import

from flask_bootstrap import Bootstrap
from keg.app import Keg

from keg_auth_ta.extensions import auth_manager, csrf, mail_ext
from keg_auth_ta.views import blueprints


class KegAuthTestApp(Keg):
    import_name = 'keg_auth_ta'
    db_enabled = True
    use_blueprints = blueprints
    keyring_enable = False

    def on_init_complete(self):
        auth_manager.init_app(self)
        csrf.init_app(self)
        mail_ext.init_app(self)

        if Bootstrap is not None:
            Bootstrap(self)

        return self


if __name__ == '__main__':
    from keg_auth_ta import app
    app.KegAuthTestApp.cli.main()
