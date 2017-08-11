from kegauth.libs.testing import CLIBase


class TestVersion(CLIBase):
    cmd_name = 'version'

    def test_output(self):
        result = self.invoke()
        assert 'version' in result.output


class TestHello(CLIBase):
    cmd_name = 'hello'

    def test_default(self):
        result = self.invoke()
        assert 'Hello World!' in result.output

    def test_argument(self):
        result = self.invoke('Fred')
        assert 'Hello Fred!' in result.output
