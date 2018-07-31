from __future__ import absolute_import

from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect
from keg_auth import AuthManager, AuthMailManager, JwtAuthenticator

from keg_auth_ta.grids import Grid

csrf = CSRFProtect()

mail_ext = Mail()
_endpoints = {'after-login': 'public.home'}
auth_mail_manager = AuthMailManager(mail_ext)
auth_manager = AuthManager(mail_manager=auth_mail_manager, endpoints=_endpoints, grid_cls=Grid,
                           secondary_authenticators=[JwtAuthenticator])
