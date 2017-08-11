import click.testing

import kegauth.cli as cli


def invoke_command(cli_cmd, *args, **kwargs):
    exit_code = kwargs.pop('exit_code', 0)
    runner = kwargs.pop('runner', None) or click.testing.CliRunner()
    env = kwargs.pop('env', {})

    result = runner.invoke(cli_cmd, args, env=env, catch_exceptions=False)

    error_message = 'Command exit code {}, expected {}.  Result output follows:\n{}'
    assert result.exit_code == exit_code, error_message.format(result.exit_code, exit_code,
                                                               result.output)
    return result


class CLIBase(object):
    cli_cmd = cli.kegauth
    cmd_name = None

    @classmethod
    def setup_class(cls):
        cls.runner = click.testing.CliRunner()

    def invoke(self, *args, **kwargs):
        cmd_name = kwargs.pop('cmd_name', self.cmd_name)
        invoke_args = cmd_name.split(' ') + list(args)
        kwargs['runner'] = self.runner
        return invoke_command(self.cli_cmd, *invoke_args, **kwargs)
