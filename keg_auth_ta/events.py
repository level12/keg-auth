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
                NavItem('User Manage', NavURL('private.secret2')),
                NavItem('Secret View', NavURL('private.secret_nested'), class_='my-link-class'),
                class_='my-group-class'
            ),
            NavItem(
                'Menu-Group',
                NavItem('User Manage 2', NavURL('auth.user:list')),
                NavItem('User Manage 3', NavURL('auth.user:list'), icon_class='fas fa-ad'),
                nav_group='auth',
                icon_class='fas fa-bomb'
            ),
        )
    )
