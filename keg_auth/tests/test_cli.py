from blazeutils.containers import LazyDict
from keg.testing import CLIBase
import mock

from keg_auth_ta.model import entities as ents


class TestCLI(CLIBase):

    def setup(self):
        ents.User.delete_cascaded()

    def test_help_options(self):
        result = self.invoke('auth')
        assert 'create-user' in result.output

    @mock.patch('keg.current_app.auth_manager.create_user_cli', autospec=True, spec_set=True)
    def test_create_user_mock(self, m_cli_create_user):
        """ We mock in this test to more accurately test the URL creation. """
        user = LazyDict(id=3, _token_plain='1234')
        m_cli_create_user.return_value = user

        result = self.invoke('auth', 'create-user', 'foo@bar.com', 'abc', 'def')

        assert 'User created.  Email sent with verification URL.' in result.output
        assert 'Verification URL: http://keg.example.com/verify-account/3/1234' in result.output

        m_cli_create_user.assert_called_once_with(email='foo@bar.com', extra_args=('abc', 'def'))

    @mock.patch('keg.current_app.auth_manager.create_user_cli', autospec=True, spec_set=True)
    def test_create_superuser_mock(self, m_cli_create_user):
        """ We mock in this test to more accurately test the URL creation. """
        user = LazyDict(id=3, _token_plain='1234')
        m_cli_create_user.return_value = user

        result = self.invoke('auth', 'create-superuser', 'foo@bar.com')

        assert 'User created.  Email sent with verification URL.' in result.output
        assert 'Verification URL: http://keg.example.com/verify-account/3/1234' in result.output

        m_cli_create_user.assert_called_once_with(email='foo@bar.com', extra_args=(),
                                                  is_superuser=True)

    def test_create_user_integration(self):
        result = self.invoke('auth', 'create-user', 'foo@bar.com')

        assert 'User created.  Email sent with verification URL.' in result.output

    def test_command_extension(self):
        result = self.invoke('auth', 'command-extension')

        assert 'verified' in result.output
