from pathlib import Path
import subprocess
import sys

import click


def auth_cli_extensions(app):
    @app.auth_manager.cli_group.command('command-extension')
    def command_extension():
        """ Demonstrate extending the auth CLI group.

            The AuthManager holds the CLI group created for user management, but extending that
            group is not as simple as it could be. To have access to the auth manager, we must
            have an active app context, so the command extension gets wrapped in a function,
            which is called via an event handler when the app is ready.
        """
        click.echo('verified')

    @app.cli.command('verify-translations', help='Verifies all strings marked for translation')
    def verify_translations():
        from pathlib import Path
        from morphi.messages.validation import check_translations

        root_path = Path(__file__).resolve().parent.parent
        check_translations(
            root_path,
            'keg_auth',
            ignored_strings = {
                'Email',
            }
        )
