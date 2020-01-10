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

        assert 'User created.\nEmail sent with verification URL.' in result.output
        assert 'Verification URL: http://keg.example.com/verify-account/3/1234' in result.output

        m_cli_create_user.assert_called_once_with(email='foo@bar.com', extra_args=('abc', 'def'),
                                                  is_superuser=False, mail_enabled=True)

    @mock.patch('keg.current_app.auth_manager.create_user_cli', autospec=True, spec_set=True)
    def test_create_superuser_mock(self, m_cli_create_user):
        """ We mock in this test to more accurately test the URL creation. """
        user = LazyDict(id=3, _token_plain='1234')
        m_cli_create_user.return_value = user

        result = self.invoke('auth', 'create-user', '--as-superuser', 'foo@bar.com')

        assert 'User created.\nEmail sent with verification URL.' in result.output
        assert 'Verification URL: http://keg.example.com/verify-account/3/1234' in result.output

        m_cli_create_user.assert_called_once_with(email='foo@bar.com', extra_args=(),
                                                  is_superuser=True, mail_enabled=True)

    @mock.patch('keg.current_app.auth_manager.mail_manager.send_new_user',
                autospec=True, spec_set=True)
    def test_create_user_integration(self, m_send):
        result = self.invoke('auth', 'create-user', 'foo@bar.com')

        output_parts = result.output.split('/')
        token = output_parts[-1].strip()
        user_id = output_parts[-2]

        assert 'User created.\nEmail sent with verification URL.' in result.output
        assert m_send.call_count

        user = ents.User.query.get(user_id)
        assert user.token_verify(token)

    @mock.patch('keg.current_app.auth_manager.mail_manager', None)
    def test_create_user_no_mail_by_manager(self):
        result = self.invoke('auth', 'create-user', 'foo@bar.com')

        assert 'User created.' in result.output
        assert 'Email sent with verification URL.' not in result.output

    @mock.patch('keg.current_app.auth_manager.mail_manager.send_new_user',
                autospec=True, spec_set=True)
    def test_create_user_no_mail_by_flag(self, m_send):
        result = self.invoke('auth', 'create-user', '--no-mail', 'foo@bar.com')

        assert 'User created.' in result.output
        assert 'Email sent with verification URL.' not in result.output
        assert 'Verification URL: http://keg.example.com/verify-account' in result.output
        assert not m_send.call_count

    @mock.patch('keg_auth.cli.click.prompt', return_value='Hello123!', autospec=True, spec_set=True)
    def test_set_password(self, m_prompt):
        ents.User.testing_create(email='test@level12.com')
        self.invoke('auth', 'set-password', 'test@level12.com')
        m_prompt.assert_called_once_with('Password', hide_input=True, confirmation_prompt=True)
        assert ents.User.get_by(email='test@level12.com').password == 'Hello123!'

    @mock.patch('keg_auth.cli.click.echo', autospec=True, spec_set=True)
    def test_set_password_error(self, m_echo):
        self.invoke('auth', 'set-password', 'test@dne.com')
        m_echo.assert_called_once_with('Unknown user', err=True)

    def test_command_extension(self):
        result = self.invoke('auth', 'command-extension')

        assert 'verified' in result.output
