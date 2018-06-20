import flask
import flask_jwt_extended
import mock
import pytest

from keg_auth.libs.authenticators import KegAuthenticator, JwtAuthenticator

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
                KegAuthenticator.get_authenticated_user() is not None
            )


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
        assert (auth_user is not None) == (JwtAuthenticator.get_authenticated_user() is not None)
        if auth_user:
            login_user.assert_called_once_with(auth_user)
        else:
            assert login_user.call_count == 0

    def test_create_access_token(self):
        user = User.testing_create()
        jwt = JwtAuthenticator(flask.current_app)
        token = jwt.create_access_token(user)
        assert flask_jwt_extended.decode_token(token)['identity'] == user.session_key
