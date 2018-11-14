import click
import keg

from keg_auth.extensions import gettext as _


def add_cli_to_app(app, cli_group_name, user_args=['email']):

    @app.cli.group(cli_group_name)
    def auth():
        """ User and authentication related commands."""

    # note: no group attached here. We will apply the arguments and group it below
    @click.argument('extra_args', nargs=-1)
    @click.option('--as-superuser', is_flag=True)
    @click.option('--no-mail', is_flag=True)
    def _create_user(as_superuser, no_mail, **kwargs):
        """ Create a user.

            Create a user record with the given required args and (if a mail manager is
            configured) send them an email with URL and token to set their password.  Any
            EXTRA_ARGS will be sent to the auth manager for processing.
        """
        auth_manager = keg.current_app.auth_manager
        user = auth_manager.create_user_cli(is_superuser=as_superuser, mail_enabled=not no_mail,
                                            **kwargs)
        click.echo(_('User created.'))
        if auth_manager.mail_manager:
            if not no_mail:
                click.echo(_('Email sent with verification URL.'))
            verification_url = auth_manager.mail_manager.verify_account_url(user)
            click.echo(_('Verification URL: {url}').format(url=verification_url))

    # dress up _create_user as needed
    user_args.reverse()
    create_user = _create_user
    for arg in user_args:
        create_user = click.argument(arg)(create_user)
    auth.command('create-user')(create_user)

    app.auth_manager.cli_group = auth
