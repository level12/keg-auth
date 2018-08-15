from keg.signals import app_ready

from keg_auth import NavItem, NavURL

from keg_auth_ta.cli import auth_cli_extensions


@app_ready.connect
def init_app_cli(app):
    auth_cli_extensions(app)


@app_ready.connect
def init_navigation(app):
    app.auth_manager.add_navigation_menu(
        'main',
        NavItem(
            NavItem('Home', NavURL('public.home')),
            NavItem(
                'Sub-Menu',
                NavItem('User Manage', NavURL('auth.user:list')),
                NavItem('Secret View', NavURL('private.secret_nested')),
            ),
        )
    )
