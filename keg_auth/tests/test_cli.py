import arrow
import mock
from blazeutils.containers import LazyDict
from keg.testing import CLIBase

from keg_auth.model.entity_registry import RegistryError
from keg_auth_ta.model import entities as ents


class TestCLI(CLIBase):

    def setup_method(self):
        ents.UserNoEmail.delete_cascaded()
        ents.User.delete_cascaded()
        ents.Attempt.delete_cascaded()

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

    @mock.patch('keg.current_app.auth_manager.mail_manager.send_new_user',
                autospec=True, spec_set=True)
    def test_create_user_user_args_integration(self, m_send):
        result = self.invoke('--profile', 'TestProfileUserArgs', 'auth', 'create-user',
                             'Bob Smith', 'bob@example.com')

        output_parts = result.output.split('/')
        user_id = output_parts[-2]

        user = ents.User.query.get(user_id)
        assert user.email == 'bob@example.com'
        assert user.name == 'Bob Smith'

        result = self.invoke('--profile', 'TestProfileUserArgs', 'auth', 'create-user',
                             'Joe Smith', 'joe@example.com')
        output_parts = result.output.split('/')
        user_id = output_parts[-2]

        user = ents.User.query.get(user_id)
        assert user.email == 'joe@example.com'
        assert user.name == 'Joe Smith'

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

    def test_set_password(self):
        ents.User.fake(email='test@level12.com')
        input_ = 'Hello123!\nHello123!'
        result = self.invoke('auth', 'set-password', 'test@level12.com', input=input_)
        assert result.stdout == 'Password: \nRepeat for confirmation: \n'

        assert ents.User.get_by(email='test@level12.com').password == 'Hello123!'

    def test_set_invalid_password(self):
        ents.User.fake(email='test@level12.com')
        input_ = 'Hello\nHello123!\nHello123!'
        result = self.invoke('auth', 'set-password', 'test@level12.com', input=input_)
        assert result.stdout == (
            'Password: \n'
            'Password does not meet the following restrictions:\n'
            '\t• Password must be at least 8 characters long\n'
            'Error: The value you entered was invalid.\n'
            'Password: \n'
            'Repeat for confirmation: \n'
        )

        assert ents.User.get_by(email='test@level12.com').password == 'Hello123!'

    @mock.patch('keg_auth.cli.click.echo', autospec=True, spec_set=True)
    def test_set_password_error(self, m_echo):
        self.invoke('auth', 'set-password', 'test@dne.com')
        m_echo.assert_called_once_with('Unknown user', err=True)

    def test_command_extension(self):
        result = self.invoke('auth', 'command-extension')

        assert 'verified' in result.output

    @mock.patch('keg.cli.click.echo', autospec=True, spec_set=True)
    def test_purge_attempts(self, m_echo):
        username = 'foo@bar.com'
        for i in range(0, 3):
            for attempt_type in ['login', 'reset']:
                for username in ['foo@test.com', 'bar@test.com']:
                    ents.Attempt.fake(
                        user_input=username,
                        attempt_type=attempt_type,
                        datetime_utc=arrow.utcnow().shift(days=-i)
                    )

        # Delete all attempts older than 2 days.
        assert ents.Attempt.query.count() == 12
        self.invoke('auth', 'purge-attempts', '--older-than=2')
        m_echo.assert_called_once_with('Deleted 4 attempts.')
        assert ents.Attempt.query.count() == 8

        # Delete all attempts for username.
        m_echo.reset_mock()
        self.invoke('auth', 'purge-attempts', '--username=foo@test.com')
        m_echo.assert_called_once_with('Deleted 4 attempts.')
        assert ents.Attempt.query.count() == 4

        # Delete all login attempts.
        m_echo.reset_mock()
        self.invoke('auth', 'purge-attempts', '--type=login')
        m_echo.assert_called_once_with('Deleted 2 attempts.')
        assert ents.Attempt.query.count() == 2

        # Delete all attempts.
        m_echo.reset_mock()
        self.invoke('auth', 'purge-attempts')
        m_echo.assert_called_once_with('Deleted 2 attempts.')
        assert ents.Attempt.query.count() == 0

    @mock.patch('keg.cli.click.echo', autospec=True, spec_set=True)
    @mock.patch('keg.current_app.auth_manager.entity_registry.get_entity_cls',
                autospec=True, spec_set=True, side_effect=RegistryError)
    def test_purge_attempts_no_attempt_registered(self, m_ent_registry, m_echo):
        self.invoke('auth', 'purge-attempts', '--username=foo@bar.com')
        m_echo.assert_called_once_with('No attempt class has been registered.')
