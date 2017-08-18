import click
import keg


def add_cli_to_app(app, cli_group_name):

    @app.cli.group(cli_group_name)
    def auth():
        """ User and authentication related commands."""

    @auth.command('create-user')
    @click.argument('email')
    @click.argument('extra_args', nargs=-1)
    def create_user(email, extra_args):
        """ Create a user.

            Create a user record with the given EMAIL address and send them an email with URL
            and token to set their password.  Any EXTRA_ARGS will be sent to the auth manager
            for processing.
        """
        auth_manager = keg.current_app.auth_manager
        user = auth_manager.create_user_cli(email, extra_args)
        verification_url = auth_manager.verify_account_url(user)
        click.echo('User created.  Email sent with verification URL.')
        click.echo('Verification URL: {}'.format(verification_url))
