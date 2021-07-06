import click
import keg

from keg_auth.model import get_username_key
from keg_auth.extensions import gettext as _
from keg_auth.libs.authenticators import PasswordPolicyError
from keg_auth.model.entity_registry import RegistryError


class PasswordType(click.ParamType):
    name = 'password'

    def __init__(self, policy, user):
        self.policy = policy
        self.user = user

    def convert(self, value, param, ctx):
        if not isinstance(value, str):
            self.fail(_('Password must be a string'), param, ctx)

        errors = []
        for check in self.policy.password_checks():
            try:
                check(value, self.user)
            except PasswordPolicyError as e:
                errors.append(str(e))

        if errors:
            error_list = '\n'.join('\t\N{BULLET} {}'.format(e) for e in errors)
            message = _('Password does not meet the following restrictions:\n{errs}',
                        errs=error_list)

            # because we hide the input, click also hides the error message, so echo manually
            click.echo(message)
            self.fail(
                message,
                param,
                ctx,
            )
        return value


def add_cli_to_app(app, cli_group_name, user_args=('email',)):

    @app.cli.group(cli_group_name)
    def auth():
        """ User and authentication related commands."""

    @auth.command('set-password', short_help='Set a user\'s password')
    @click.argument('username')
    def set_user_password(username):
        auth_manager = keg.current_app.auth_manager
        user_ent = auth_manager.entity_registry.user_cls
        user = user_ent.get_by(**{get_username_key(user_ent): username})

        if user is None:
            click.echo('Unknown user', err=True)
            return

        password_policy = auth_manager.password_policy_cls()
        password = click.prompt(
            'Password',
            type=PasswordType(password_policy, user),
            hide_input=True,
            confirmation_prompt=True
        )
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
    create_user = _create_user
    for arg in reversed(user_args):
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
