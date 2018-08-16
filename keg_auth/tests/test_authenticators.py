import flask
import flask_jwt_extended
import jwt
import ldap
import mock
import pytest

from keg_auth.libs import authenticators as auth

from keg_auth_ta.model.entities import User


class TestKegAuthenticator:
    def test_user_not_found(self):
        with pytest.raises(auth.UserNotFound):
            authenticator = auth.KegAuthenticator(app=flask.current_app)
            authenticator.verify_user(login_id='nobodybythisnamehere')

    def test_user_not_active(self):
        user = User.testing_create(is_enabled=False)
        with pytest.raises(auth.UserInactive) as e_info:
            authenticator = auth.KegAuthenticator(app=flask.current_app)
            authenticator.verify_user(login_id=user.email)
        assert e_info.value.user is user

    def test_user_bad_password(self):
        user = User.testing_create()
        with pytest.raises(auth.UserInvalidAuth) as e_info:
            authenticator = auth.KegAuthenticator(app=flask.current_app)
            authenticator.verify_user(login_id=user.email, password='cannotpossiblybethis')
        assert e_info.value.user is user

    def test_user_verified(self):
        user = User.testing_create()
        authenticator = auth.KegAuthenticator(app=flask.current_app)
        found_user = authenticator.verify_user(login_id=user.email, password=user._plaintext_pass)
        assert user is found_user


class TestLdapAuthenticator:
    def setup(self):
        flask.current_app.config['KEGAUTH_LDAP_SERVER_URL'] = 'abc123'
        flask.current_app.config['KEGAUTH_LDAP_DN_FORMAT'] = '{}'

    def test_user_not_found(self):
        with pytest.raises(auth.UserNotFound):
            authenticator = auth.LdapAuthenticator(app=flask.current_app)
            authenticator.verify_user(login_id='nobodybythisnamehere')

    def test_user_not_active(self):
        user = User.testing_create(is_enabled=False)
        with pytest.raises(auth.UserInactive) as e_info:
            authenticator = auth.LdapAuthenticator(app=flask.current_app)
            authenticator.verify_user(login_id=user.email)
        assert e_info.value.user is user

    @mock.patch('ldap.initialize', autospec=True, spec_set=True)
    def test_no_server_url_set(self, mocked_ldap):
        del flask.current_app.config['KEGAUTH_LDAP_SERVER_URL']

        user = User.testing_create()
        authenticator = auth.LdapAuthenticator(app=flask.current_app)
        with pytest.raises(Exception) as e_info:
            authenticator.verify_password(user, None)
        assert 'KEGAUTH_LDAP_SERVER_URL' in str(e_info.value)

    @mock.patch('ldap.initialize', autospec=True, spec_set=True)
    def test_no_dn_format_set(self, mocked_ldap):
        del flask.current_app.config['KEGAUTH_LDAP_DN_FORMAT']

        user = User.testing_create()
        authenticator = auth.LdapAuthenticator(app=flask.current_app)
        with pytest.raises(Exception) as e_info:
            authenticator.verify_password(user, None)
        assert 'KEGAUTH_LDAP_DN_FORMAT' in str(e_info.value)

    @mock.patch('ldap.initialize', autospec=True, spec_set=True)
    def test_unsuccessful_authentication(self, mocked_ldap):
        mocked_ldap.return_value.simple_bind_s.side_effect = ldap.INVALID_CREDENTIALS()

        user = User.testing_create()
        authenticator = auth.LdapAuthenticator(app=flask.current_app)
        success = authenticator.verify_password(user, 'foo')

        assert mocked_ldap.call_count
        assert success is False

    @mock.patch('ldap.initialize', autospec=True, spec_set=True)
    def test_invalid_dn_syntax(self, mocked_ldap):
        mocked_ldap.return_value.simple_bind_s.side_effect = ldap.INVALID_DN_SYNTAX()

        user = User.testing_create()
        authenticator = auth.LdapAuthenticator(app=flask.current_app)
        success = authenticator.verify_password(user, 'foo')

        assert mocked_ldap.call_count
        assert success is False

    @mock.patch('ldap.initialize', autospec=True, spec_set=True)
    def test_unsuccessful_authentication_wrong_result(self, mocked_ldap):
        mocked_ldap.return_value.simple_bind_s.return_value = (0, )

        user = User.testing_create()
        authenticator = auth.LdapAuthenticator(app=flask.current_app)
        success = authenticator.verify_password(user, 'foo')

        assert mocked_ldap.call_count
        assert success is False

    @mock.patch('ldap.initialize', autospec=True, spec_set=True)
    def test_successful_authentication(self, mocked_ldap):
        mocked_ldap.return_value.simple_bind_s.return_value = (ldap.RES_BIND, )

        user = User.testing_create()
        authenticator = auth.LdapAuthenticator(app=flask.current_app)
        success = authenticator.verify_password(user, 'foo')

        assert mocked_ldap.call_count
        assert success is True

    @mock.patch('ldap.initialize', autospec=True, spec_set=True)
    def test_debug_override(self, mocked_ldap):
        flask.current_app.config['KEGAUTH_LDAP_TEST_MODE'] = True

        user = User.testing_create()
        authenticator = auth.LdapAuthenticator(app=flask.current_app)
        success = authenticator.verify_password(user, 'foo')

        assert not mocked_ldap.call_count
        assert success is True


class TestJwtRequestLoader:
    @pytest.mark.parametrize('is_authenticated', [
        User.testing_create, lambda: None
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
        user = User.testing_create()
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
        user = User.testing_create(is_enabled=False)
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
        user = User.testing_create()
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
        user = User.testing_create()
        jwt_auth = auth.JwtRequestLoader(flask.current_app)
        token = jwt_auth.create_access_token(user)
        assert flask_jwt_extended.decode_token(token)['identity'] == user.session_key
