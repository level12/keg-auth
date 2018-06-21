from keg.signals import app_ready

from keg_auth import Node, Route

from keg_auth_ta.cli import auth_cli_extensions


@app_ready.connect
def init_app_cli(app):
    auth_cli_extensions(app)


@app_ready.connect
def init_navigation(app):
    app.auth_manager.add_navigation_menu(
        'main',
        Node(
            Node('Home', Route('public.home')),
            Node(
                'Sub-Menu',
                Node('User Manage', Route('auth.user:list')),
                Node('Secret View', Route('private.secret_nested')),
            ),
        )
    )
