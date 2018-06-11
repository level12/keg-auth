import click
import keg


def add_cli_to_app(app, cli_group_name, user_args=['email']):

    @app.cli.group(cli_group_name)
    def auth():
        """ User and authentication related commands."""

    # note: no group attached here. We will apply the arguments and group it below
    @click.argument('extra_args', nargs=-1)
    def _create_user(**kwargs):
        """ Create a user.

            Create a user record with the given required args and send them an email with URL
            and token to set their password.  Any EXTRA_ARGS will be sent to the auth manager
            for processing.
        """
        auth_manager = keg.current_app.auth_manager
        user = auth_manager.create_user_cli(**kwargs)
        verification_url = auth_manager.verify_account_url(user)
        click.echo('User created.  Email sent with verification URL.')
        click.echo('Verification URL: {}'.format(verification_url))

    # dress up _create_user as needed
    user_args.reverse()
    create_user = _create_user
    for arg in user_args:
        create_user = click.argument(arg)(create_user)
    auth.command('create-user')(create_user)

    app.auth_manager.cli_group = auth
