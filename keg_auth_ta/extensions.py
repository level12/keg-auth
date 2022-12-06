from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect
from keg_auth import AuthManager, AuthMailManager, JwtRequestLoader, AuthEntityRegistry
import webgrid
from webgrid.flask import WebGrid as GridManager


class Grid(webgrid.BaseGrid):
    manager = GridManager()
    session_on = True


csrf = CSRFProtect()

permissions = (
    'auth-manage',
    'permission1',
    'permission2',
)

auth_entity_registry = AuthEntityRegistry()
mail_ext = Mail()
_endpoints = {'after-login': 'public.home'}
auth_mail_manager = AuthMailManager(mail_ext)
auth_manager = AuthManager(mail_manager=auth_mail_manager, endpoints=_endpoints, grid_cls=Grid,
                           request_loaders=[JwtRequestLoader], entity_registry=auth_entity_registry,
                           permissions=permissions)
