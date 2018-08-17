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
