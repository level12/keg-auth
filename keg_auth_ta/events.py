from keg.signals import app_ready

from keg_auth_ta.cli import auth_cli_extensions


@app_ready.connect
def init_app_cli(app):
    auth_cli_extensions(app)
