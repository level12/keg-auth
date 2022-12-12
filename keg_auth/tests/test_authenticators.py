import string
from unittest import mock

import flask
import flask_jwt_extended
import jwt
import ldap
import pytest

from keg_auth.libs import authenticators as auth, get_domain_from_email
from keg_auth.tests.utils import oauth_profile
from keg_auth_ta.model.entities import User, UserNoEmail


class TestKegAuthenticator:
    def test_user_not_found(self):
        with pytest.raises(auth.UserNotFound):
            authenticator = auth.KegAuthenticator(app=flask.current_app)
            authenticator.verify_user(login_id='nobodybythisnamehere')

    def test_user_not_active(self):
        user = User.fake(is_enabled=False)
        with pytest.raises(auth.UserInactive) as e_info:
            authenticator = auth.KegAuthenticator(app=flask.current_app)
            authenticator.verify_user(login_id=user.email)
        assert e_info.value.user is user

    def test_user_bad_password(self):
        user = User.fake()
        with pytest.raises(auth.UserInvalidAuth) as e_info:
            authenticator = auth.KegAuthenticator(app=flask.current_app)
            authenticator.verify_user(login_id=user.email, password='cannotpossiblybethis')
        assert e_info.value.user is user

    def test_user_verified(self):
        user = User.fake()
        authenticator = auth.KegAuthenticator(app=flask.current_app)
        found_user = authenticator.verify_user(login_id=user.email, password=user._plaintext_pass)
        assert user is found_user

    def test_user_excluded(self):
        user = User.fake()
        authenticator = auth.KegAuthenticator(app=flask.current_app)
        authenticator.domain_exclusions = [get_domain_from_email(user.email)]
        with pytest.raises(auth.UserNotFound):
            authenticator.verify_user(login_id=user.email, password=user._plaintext_pass)

    def test_unverified_user(self):
        user = User.fake()
        user.is_verified = False
        authenticator = auth.KegAuthenticator(app=flask.current_app)
        with pytest.raises(auth.UserInactive) as e_info:
            authenticator.verify_user(login_id=user.email, password=user._plaintext_pass)
        assert e_info.value.user is user

        found_user = authenticator.verify_user(login_id=user.email, password=user._plaintext_pass,
                                               allow_unverified=True)
        assert user is found_user

    def test_user_case_insensitive(self):
        from keg import db
        from sqlalchemy import text

        user = User.fake(email='abc@foo.bar')

        # Downstream in the process of creating a user, the email will be set to all lowercase
        # So we need to manually set it to capital letters to test the fix
        with db.db.engine.connect() as connection:
            connection.execute(
                text("UPDATE users SET email = 'ABC@Foo.Bar' WHERE email = 'abc@foo.bar'")
            )
        authenticator = auth.KegAuthenticator(app=flask.current_app)
        found_user = authenticator.verify_user(login_id='aBc@Foo.Bar',
                                               password=user._plaintext_pass)
        assert found_user is not None
        assert found_user.id == user.id

    @mock.patch.dict(
        'flask.current_app.config',
        {
            'KEGAUTH_OAUTH_PROFILES': [
                oauth_profile(domain_filter='bar.baz'),
                oauth_profile(domain_filter=('foo.co', 'foo.mo')),
            ]
        }
    )
    def test_loads_oauth_exclusions(self):
        authenticator = auth.KegAuthenticator(app=flask.current_app)
        assert authenticator.domain_exclusions == ['bar.baz', 'foo.co', 'foo.mo']

    def test_domain_excluded(self):
        authenticator = auth.KegAuthenticator(app=flask.current_app)
        assert not authenticator.is_domain_excluded('foo@bar.baz')
        authenticator.domain_exclusions = ['bar.baz', 'foo.co', 'foo.mo']
        assert authenticator.is_domain_excluded('foo@bar.baz')
        assert not authenticator.is_domain_excluded('foo@bar.co')


class TestOAuthAuthenticator:
    @mock.patch.dict('flask.current_app.config', {'KEGAUTH_OAUTH_PROFILES': [oauth_profile()]})
    def test_profiles_loaded(self):
        auth.OAuthAuthenticator(app=flask.current_app)
        assert flask.current_app.auth_manager.oauth.create_client('google')
        assert not flask.current_app.auth_manager.oauth.create_client('twitter')

    @mock.patch.dict(
        'flask.current_app.config',
        {'KEGAUTH_OAUTH_PROFILES': [oauth_profile(oauth_client_kwargs={'name': 'foo'})]}
    )
    @mock.patch('authlib.integrations.flask_client.OAuth', autospec=True, spec_set=True)
    def test_kwargs_passed_to_oauth_client(self, m_oauth):
        auth.OAuthAuthenticator(app=flask.current_app)
        m_oauth.return_value.register.assert_called_once_with(name='foo')

    @mock.patch.dict('flask.current_app.config', {'KEGAUTH_OAUTH_PROFILES': [oauth_profile()]})
    def test_user_not_found(self):
        with pytest.raises(auth.UserNotFound):
            authenticator = auth.OAuthAuthenticator(app=flask.current_app)
            authenticator.verify_user(
                profile_name='google', login_id='nobodybythisnamehere@mycompany.biz'
            )

    @mock.patch.dict('flask.current_app.config', {'KEGAUTH_OAUTH_PROFILES': [oauth_profile()]})
    def test_user_not_active(self):
        user = User.fake(is_enabled=False, email='usernotfound@mycompany.biz')
        with pytest.raises(auth.UserInactive) as e_info:
            authenticator = auth.OAuthAuthenticator(app=flask.current_app)
            authenticator.verify_user(profile_name='google', login_id=user.email)
        assert e_info.value.user is user

    @mock.patch.dict('flask.current_app.config', {'KEGAUTH_OAUTH_PROFILES': [oauth_profile()]})
    def test_user_verified(self):
        user = User.fake(email='userverified@mycompany.biz')
        authenticator = auth.OAuthAuthenticator(app=flask.current_app)
        found_user = authenticator.verify_user(profile_name='google', login_id=user.email)
        assert user is found_user

    @mock.patch.dict('flask.current_app.config', {'KEGAUTH_OAUTH_PROFILES': [oauth_profile()]})
    def test_user_unverified(self):
        user = User.fake(email='userunverified@mycompany.biz')
        user.is_verified = False
        authenticator = auth.OAuthAuthenticator(app=flask.current_app)
        found_user = authenticator.verify_user(profile_name='google', login_id=user.email)
        assert user is found_user
        assert user.is_verified

    @mock.patch.dict('flask.current_app.config', {'KEGAUTH_OAUTH_PROFILES': [oauth_profile()]})
    def test_domain_exclusion(self):
        user = User.fake(email='userverified@someothercompany.co')
        authenticator = auth.OAuthAuthenticator(app=flask.current_app)
        with pytest.raises(auth.UserNotFound):
            authenticator.verify_user(profile_name='google', login_id=user.email)

    def test_bad_profile(self):
        user = User.fake()
        authenticator = auth.OAuthAuthenticator(app=flask.current_app)
        with pytest.raises(Exception, match='.*foo is not configured'):
            authenticator.verify_user(profile_name='foo', login_id=user.email)


class TestLdapAuthenticator:
    def setup_method(self):
        flask.current_app.config['KEGAUTH_LDAP_SERVER_URL'] = 'abc123'
        flask.current_app.config['KEGAUTH_LDAP_DN_FORMAT'] = '{}'

    @mock.patch('ldap.initialize', autospec=True, spec_set=True)
    def test_user_not_found(self, mocked_ldap):
        mocked_ldap.return_value.simple_bind_s.return_value = (ldap.RES_BIND, )

        authenticator = auth.LdapAuthenticator(app=flask.current_app)
        success = authenticator.verify_user(login_id='nobodybythisnamehere', password='foo')
        assert mocked_ldap.call_count
        assert success
        assert User.get_by(username='nobodybythisnamehere')

    @mock.patch('ldap.initialize', autospec=True, spec_set=True)
    def test_user_not_active(self, mocked_ldap):
        # internal flag should have no effect on LDAP auth
        mocked_ldap.return_value.simple_bind_s.return_value = (ldap.RES_BIND, )
        user = User.fake(is_enabled=False)
        authenticator = auth.LdapAuthenticator(app=flask.current_app)
        assert authenticator.verify_user(login_id=user.email)

    @mock.patch('ldap.initialize', autospec=True, spec_set=True)
    def test_no_server_url_set(self, mocked_ldap):
        del flask.current_app.config['KEGAUTH_LDAP_SERVER_URL']

        user = User.fake()
        authenticator = auth.LdapAuthenticator(app=flask.current_app)
        with pytest.raises(Exception) as e_info:
            authenticator.verify_password(user, None)
        assert 'KEGAUTH_LDAP_SERVER_URL' in str(e_info.value)

    @mock.patch('ldap.initialize', autospec=True, spec_set=True)
    def test_no_dn_format_set(self, mocked_ldap):
        del flask.current_app.config['KEGAUTH_LDAP_DN_FORMAT']

        user = User.fake()
        authenticator = auth.LdapAuthenticator(app=flask.current_app)
        with pytest.raises(Exception) as e_info:
            authenticator.verify_password(user, None)
        assert 'KEGAUTH_LDAP_DN_FORMAT' in str(e_info.value)

    @mock.patch('ldap.initialize', autospec=True, spec_set=True)
    def test_unsuccessful_authentication(self, mocked_ldap):
        mocked_ldap.return_value.simple_bind_s.side_effect = ldap.INVALID_CREDENTIALS()

        user = User.fake()
        authenticator = auth.LdapAuthenticator(app=flask.current_app)
        success = authenticator.verify_password(user, 'foo')

        assert mocked_ldap.call_count
        assert success is False

    @mock.patch('ldap.initialize', autospec=True, spec_set=True)
    def test_invalid_dn_syntax(self, mocked_ldap):
        mocked_ldap.return_value.simple_bind_s.side_effect = ldap.INVALID_DN_SYNTAX()

        user = User.fake()
        authenticator = auth.LdapAuthenticator(app=flask.current_app)
        success = authenticator.verify_password(user, 'foo')

        assert mocked_ldap.call_count
        assert success is False

    @mock.patch('ldap.initialize', autospec=True, spec_set=True)
    def test_unsuccessful_authentication_wrong_result(self, mocked_ldap):
        mocked_ldap.return_value.simple_bind_s.return_value = (0, )

        user = User.fake()
        authenticator = auth.LdapAuthenticator(app=flask.current_app)
        success = authenticator.verify_password(user, 'foo')

        assert mocked_ldap.call_count
        assert success is False

    @mock.patch('ldap.initialize', autospec=True, spec_set=True)
    def test_successful_authentication(self, mocked_ldap):
        mocked_ldap.return_value.simple_bind_s.return_value = (ldap.RES_BIND, )

        user = User.fake()
        authenticator = auth.LdapAuthenticator(app=flask.current_app)
        success = authenticator.verify_password(user, 'foo')

        assert mocked_ldap.call_count
        assert success is True

    @mock.patch('ldap.initialize', autospec=True, spec_set=True)
    def test_successful_authentication_multiple_server_urls(self, mocked_ldap):
        flask.current_app.config['KEGAUTH_LDAP_SERVER_URL'] = ['abc123', 'def456', 'ghi789']
        mocked_ldap.return_value.simple_bind_s.side_effect = (
            (0,),
            (0,),
            (ldap.RES_BIND,)
        )

        user = User.fake()
        authenticator = auth.LdapAuthenticator(app=flask.current_app)
        success = authenticator.verify_password(user, 'foo')

        assert mocked_ldap.call_args_list == [
            mock.call('abc123'),
            mock.call('def456'),
            mock.call('ghi789'),
        ]
        assert success is True

    @mock.patch('ldap.initialize', autospec=True, spec_set=True)
    def test_debug_override(self, mocked_ldap):
        flask.current_app.config['KEGAUTH_LDAP_TEST_MODE'] = True

        user = User.fake()
        authenticator = auth.LdapAuthenticator(app=flask.current_app)
        success = authenticator.verify_password(user, 'foo')

        assert not mocked_ldap.call_count
        assert success is True


class TestJwtRequestLoader:
    @pytest.mark.parametrize('is_authenticated', [
        User.fake, lambda: None
    ])
    @mock.patch('keg_auth.libs.authenticators.flask_jwt_extended.verify_jwt_in_request',
                autospec=True, spec_set=True)
    @mock.patch('keg_auth.libs.authenticators.flask_jwt_extended.get_current_user',
                autospec=True, spec_set=True)
    @mock.patch('keg_auth.libs.authenticators.flask_login.login_user',
                autospec=True, spec_set=True)
    def test_user_is_authenticated(self,
                                   login_user,
                                   get_current_user,
                                   verify_jwt_in_request,
                                   is_authenticated):
        auth_user = is_authenticated()
        if not auth_user:
            verify_jwt_in_request.side_effect = flask_jwt_extended.exceptions.JWTExtendedException
        else:
            get_current_user.return_value = auth_user
        assert (auth_user is not None) == (
            auth.JwtRequestLoader.get_authenticated_user() is not None)
        if auth_user:
            login_user.assert_called_once_with(auth_user)
        else:
            assert login_user.call_count == 0

    def test_bad_token(self):
        jwt_auth = auth.JwtRequestLoader(flask.current_app)
        with mock.patch.dict(
            flask.current_app.config,
            JWT_TOKEN_LOCATION='query_string',
            JWT_QUERY_STRING_NAME='jwt',
        ):
            with flask.current_app.test_request_context('/?jwt=notgoodatall'):
                with pytest.raises(jwt.exceptions.DecodeError):
                    jwt_auth.get_authenticated_user()

    def test_missing_token(self):
        jwt_auth = auth.JwtRequestLoader(flask.current_app)
        with mock.patch.dict(
            flask.current_app.config,
            JWT_TOKEN_LOCATION='query_string',
            JWT_QUERY_STRING_NAME='jwt',
        ):
            with flask.current_app.test_request_context('/'):
                assert jwt_auth.get_authenticated_user() is None

    def test_user_not_found(self):
        user = User.fake()
        jwt_auth = auth.JwtRequestLoader(flask.current_app)
        token = jwt_auth.create_access_token(user)
        User.delete_cascaded()
        with mock.patch.dict(
            flask.current_app.config,
            JWT_TOKEN_LOCATION='query_string',
            JWT_QUERY_STRING_NAME='jwt',
        ):
            with flask.current_app.test_request_context('/?jwt={}'.format(token)):
                assert jwt_auth.get_authenticated_user() is None

    def test_user_not_active(self):
        user = User.fake(is_enabled=False)
        jwt_auth = auth.JwtRequestLoader(flask.current_app)
        token = jwt_auth.create_access_token(user)
        with mock.patch.dict(
            flask.current_app.config,
            JWT_TOKEN_LOCATION='query_string',
            JWT_QUERY_STRING_NAME='jwt',
        ):
            with flask.current_app.test_request_context('/?jwt={}'.format(token)):
                assert jwt_auth.get_authenticated_user() is None

    def test_user_verified(self):
        user = User.fake()
        jwt_auth = auth.JwtRequestLoader(flask.current_app)
        token = jwt_auth.create_access_token(user)
        with mock.patch.dict(
            flask.current_app.config,
            JWT_TOKEN_LOCATION='query_string',
            JWT_QUERY_STRING_NAME='jwt',
        ):
            with flask.current_app.test_request_context('/?jwt={}'.format(token)):
                assert jwt_auth.get_authenticated_user() is user

    def test_create_access_token(self):
        user = User.fake()
        jwt_auth = auth.JwtRequestLoader(flask.current_app)
        token = jwt_auth.create_access_token(user)
        assert flask_jwt_extended.decode_token(token)['sub'] == user.session_key


class TestPasswordPolicy:
    def setup_method(self, _):
        User.delete_cascaded()
        UserNoEmail.delete_cascaded()

    def test_check_length(self):
        user = User.fake()
        with pytest.raises(auth.PasswordPolicyError,
                           match='Password must be at least 8 characters long'):
            auth.PasswordPolicy().check_length('aBcDe1!', user)

        class LongerPolicy(auth.PasswordPolicy):
            min_length = 10

        with pytest.raises(auth.PasswordPolicyError,
                           match='Password must be at least 10 characters long'):
            LongerPolicy().check_length('aBcDeFg1!', user)

        auth.PasswordPolicy().check_length('aBcDeF1!', user)
        LongerPolicy().check_length('aBcDeFgH1!', user)

    @pytest.mark.parametrize('pw', [
        'a' * 8,
        'A' * 8,
        '1' * 8,
        'aA' * 4,
        'a1' * 4,
        '1!' * 4,
    ])
    def test_char_set_validator_failures(self, pw):
        user = User.fake()

        with pytest.raises(
            auth.PasswordPolicyError,
            match='Password must include at least 3 of lowercase letter, uppercase letter, number and/or symbol'  # noqa: E501
        ):
            auth.PasswordPolicy().check_character_set(pw, user)

    @pytest.mark.parametrize('pw', [
        'a' * 8,
        'A' * 8,
        '1' * 8,
    ])
    def test_override_min_char_types_requirement_failures(self, pw):
        user = User.fake()

        class FewerChars(auth.PasswordPolicy):
            required_min_char_types = 2

        with pytest.raises(
            auth.PasswordPolicyError,
            match='Password must include at least 2 of lowercase letter, uppercase letter, number and/or symbol'  # noqa: E501
        ):
            FewerChars().check_character_set(pw, user)

    @pytest.mark.parametrize('pw', [
        'aA' * 4,
        'A1' * 4,
        '1!' * 4,
        'aA1' * 3,
        'a1 ' * 3,
        '\t1!' * 3,
    ])
    def test_override_required_char_types_failures(self, pw):
        user = User.fake()

        class RequireWhitespace(auth.PasswordPolicy):
            required_min_char_types = 4
            required_char_types = [
                *auth.PasswordPolicy.required_char_types,
                auth.PasswordCharset('whitespace', string.whitespace)
            ]

        with pytest.raises(
            auth.PasswordPolicyError,
            match='Password must include at least 4 of lowercase letter, uppercase letter, number, symbol and/or whitespace'  # noqa: E501
        ):
            RequireWhitespace().check_character_set(pw, user)

    def test_required_char_types_one_type(self):
        user = User.fake()

        class RequireNumber(auth.PasswordPolicy):
            required_min_char_types = 1
            required_char_types = [auth.PasswordCharset('number', string.digits)]

        with pytest.raises(auth.PasswordPolicyError, match='Password must include a number'):
            RequireNumber().check_character_set('abcdefgh', user)

        RequireNumber().check_character_set('abcdefg1', user)

    @pytest.mark.parametrize('pw', [
        'aA1 ' * 3,
        'a1 !' * 3,
        '\t1!a' * 3,
    ])
    def test_override_required_char_types_success(self, pw):
        user = User.fake()

        class RequireWhitespace(auth.PasswordPolicy):
            required_min_char_types = 4
            required_char_types = [
                *auth.PasswordPolicy.required_char_types,
                auth.PasswordCharset('whitespace', string.whitespace)
            ]

        RequireWhitespace().check_character_set(pw, user)

    @pytest.mark.parametrize('pw', [
        'aaaaaaaa1!',
        'aaaaaaaaA!',
        'aaaaaaaaA1',
        'AAAAAAAA1!',
    ])
    def test_check_char_set_success(self, pw):
        user = User.fake()
        auth.PasswordPolicy().check_character_set(pw, user)

    @pytest.mark.parametrize('pw,email', [
        ('1!bob!1234', 'bob@example.com'),
        ('BoB123456!', 'bOb@example.com'),
    ])
    def test_check_does_not_contain_username_email_failures(self, pw, email):
        user = User.fake(email=email)
        with pytest.raises(auth.PasswordPolicyError, match='Password may not contain username'):
            auth.PasswordPolicy().check_does_not_contain_username(pw, user)

    @pytest.mark.parametrize('pw,username', [
        ('1!bob!1234', 'bob'),
        ('BoB123456!', 'bOb'),
    ])
    def test_check_does_not_contain_username_no_email_failures(self, pw, username):
        user = UserNoEmail.fake(username=username)
        with pytest.raises(auth.PasswordPolicyError, match='Password may not contain username'):
            auth.PasswordPolicy().check_does_not_contain_username(pw, user)

    @pytest.mark.parametrize('pw,email', [
        ('1!b0b!1234', 'bob@example.com'),
        ('B0B123456!', 'bOb@example.com'),
    ])
    def test_check_does_not_contain_username_email_success(self, pw, email):
        user = User.fake(email=email)
        auth.PasswordPolicy().check_does_not_contain_username(pw, user)

    @pytest.mark.parametrize('pw,username', [
        ('1!b0b!1234', 'bob'),
        ('B0B123456!', 'bOb'),
    ])
    def test_check_does_not_contain_username_no_email_success(self, pw, username):
        user = UserNoEmail.fake(username=username)
        auth.PasswordPolicy().check_does_not_contain_username(pw, user)
