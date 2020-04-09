import click
import keg

from keg_auth.model import get_username_key
from keg_auth.extensions import gettext as _
from keg_auth.model.entity_registry import RegistryError


def add_cli_to_app(app, cli_group_name, user_args=['email']):

    @app.cli.group(cli_group_name)
    def auth():
        """ User and authentication related commands."""

    @auth.command('set-password', short_help='Set a user\'s password')
    @click.argument('username')
    def set_user_password(username):
        user_ent = app.auth_manager.entity_registry.user_cls
        user = user_ent.get_by(**{get_username_key(user_ent): username})
        if user is None:
            click.echo('Unknown user', err=True)
            return

        password = click.prompt('Password', hide_input=True, confirmation_prompt=True)
        user.change_password(user.token_generate(), password)

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

    @click.option('--username', '--user', help='username to filter by')
    @click.option('--older-than', type=int, help='number of days')
    @click.option('--attempt-type', '--type', help='[login, reset, forgot]')
    def purge_attempts(username, older_than, attempt_type):
        """Purge authentication attempts optionally filtered by username, type, or age."""
        auth_manager = keg.current_app.auth_manager
        try:
            attempt_ent = auth_manager.entity_registry.attempt_cls
        except RegistryError:
            click.echo('No attempt class has been registered.')
            return

        count = attempt_ent.purge_attempts(
            username=username,
            older_than=older_than,
            attempt_type=attempt_type
        )
        click.echo(f'Deleted {count} attempts.')

    auth.command('purge-attempts')(purge_attempts)

    app.auth_manager.cli_group = auth
