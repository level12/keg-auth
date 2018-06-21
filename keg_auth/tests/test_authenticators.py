import flask
import flask_jwt_extended
import jwt
import mock
import pytest

from keg_auth.libs import authenticators as auth

from keg_auth_ta.model.entities import User


class TestKegAuthenticator:
    @pytest.mark.parametrize('is_authenticated', [
        User.testing_create, lambda: None
    ])
    def test_user_is_authenticated(self, is_authenticated):
        auth_user = is_authenticated()
        with mock.patch('flask_login.current_user') as current_user:  # noqa: M100, M102
            current_user.is_authenticated = auth_user is not None
            assert (auth_user is not None) == (
                auth.KegAuthenticator.get_authenticated_user() is not None
            )

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


class TestJwtAuthenticator:
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
            auth.JwtAuthenticator.get_authenticated_user() is not None)
        if auth_user:
            login_user.assert_called_once_with(auth_user)
        else:
            assert login_user.call_count == 0

    def test_bad_token(self):
        jwt_auth = auth.JwtAuthenticator(flask.current_app)
        with mock.patch.dict(
            flask.current_app.config,
            JWT_TOKEN_LOCATION='query_string',
            JWT_QUERY_STRING_NAME='jwt',
        ):
            with flask.current_app.test_request_context('/?jwt=notgoodatall'):
                with pytest.raises(jwt.exceptions.DecodeError):
                    jwt_auth.get_authenticated_user()

    def test_missing_token(self):
        jwt_auth = auth.JwtAuthenticator(flask.current_app)
        with mock.patch.dict(
            flask.current_app.config,
            JWT_TOKEN_LOCATION='query_string',
            JWT_QUERY_STRING_NAME='jwt',
        ):
            with flask.current_app.test_request_context('/'):
                assert jwt_auth.get_authenticated_user() is None

    def test_user_not_found(self):
        user = User.testing_create()
        jwt_auth = auth.JwtAuthenticator(flask.current_app)
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
        jwt_auth = auth.JwtAuthenticator(flask.current_app)
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
        jwt_auth = auth.JwtAuthenticator(flask.current_app)
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
        jwt_auth = auth.JwtAuthenticator(flask.current_app)
        token = jwt_auth.create_access_token(user)
        assert flask_jwt_extended.decode_token(token)['identity'] == user.session_key
