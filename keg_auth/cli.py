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

            Create a user record with the given required args and (if a mail manager is
            configured) send them an email with URL and token to set their password.  Any
            EXTRA_ARGS will be sent to the auth manager for processing.
        """
        auth_manager = keg.current_app.auth_manager
        user = auth_manager.create_user_cli(**kwargs)
        click.echo('User created.')
        if auth_manager.mail_manager:
            verification_url = auth_manager.mail_manager.verify_account_url(user)
            click.echo('Email sent with verification URL.')
            click.echo('Verification URL: {}'.format(verification_url))

    @click.argument('extra_args', nargs=-1)
    def _create_superuser(**kwargs):
        _create_user(is_superuser=True, **kwargs)

    # dress up _create_user as needed
    user_args.reverse()
    create_user = _create_user
    create_superuser = _create_superuser
    for arg in user_args:
        create_user = click.argument(arg)(create_user)
        create_superuser = click.argument(arg)(create_superuser)
    auth.command('create-user')(create_user)
    auth.command('create-superuser')(create_superuser)

    app.auth_manager.cli_group = auth
