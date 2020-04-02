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
        # This method is intended for a CI check on translations. To make it work, we'd have to
        # pin Babel to 2.6, though, so I'll hold off on the CI usage.
        from keg_auth.extensions import Manager, translation_manager

        def clone_manager(locales=None):
            manager = translation_manager

            return Manager(dirname=manager.dirname, locales=locales or manager.locales,
                           domain=manager.domain, package_name=manager.package_name)

        # The following strings can be treated as false positives below, since the translation will
        # equal the original string
        ignored_strings = {
            'Email',
        }

        root_path = Path(__file__).resolve().parent.parent
        setup_py = str(root_path / 'setup.py')
        subprocess.run(['python', setup_py, 'extract_messages'])
        subprocess.run(['python', setup_py, 'update_catalog', '--no-fuzzy-matching'])
        subprocess.run(['python', setup_py, 'compile_catalog'])
        subprocess.run(['python', setup_py, 'compile_json'])

        found_fuzzy = False
        untranslated_strings = []

        # check for fuzzy matches
        po_path = root_path / 'keg_auth' / 'i18n' / 'es' / 'LC_MESSAGES' / 'keg_auth.po'
        with open(po_path, mode='rb') as fp:
            contents = fp.read()
            found_fuzzy = b'#, fuzzy' in contents

        manager = clone_manager(locales=['es'])
        catalog = manager.translations._catalog
        for key, value in catalog.items():
            if key and key == value and key not in ignored_strings:
                untranslated_strings.append(key)

        # note: the strings below are intentionally left untranslated
        if found_fuzzy:
            print('Detected fuzzy translations.')

        if untranslated_strings:
            print('Did not find translations for the following strings:')
            for item in untranslated_strings:
                print('    ', item)

        if found_fuzzy or untranslated_strings:
            print('Edit the PO file and compile the catalogs.')
            sys.exit(1)

        print('No detected translation issues.')
