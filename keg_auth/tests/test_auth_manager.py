import flask
import mock

from keg_auth.core import AuthManager
from keg_auth.libs.authenticators import KegAuthenticator, JwtAuthenticator

from keg_auth_ta.app import mail_ext
from keg_auth_ta.model import entities as ents


class TestAuthManager(object):
    def setup(self):
        ents.User.delete_cascaded()
        self.am = flask.current_app.auth_manager

    def test_create_user(self):
        with mail_ext.record_messages() as outbox:
            user = self.am.create_user(dict(email=u'foo@bar.com'))

        assert len(outbox) == 1
        assert outbox[0].subject == '[KA Demo] User Welcome & Verification'

        assert user.email == 'foo@bar.com'
        assert user.token
        assert user._token_plain
        assert ents.User.query.count() == 1

    @mock.patch('keg_auth.core.model.initialize_mappings')
    def test_model_initialized_only_once(self, m_init):
        self.am.init_app(flask.current_app)
        assert not m_init.called

    @mock.patch('keg_auth.core.KegAuthenticator')
    def test_authenticators_initialized_only_once(self, m_init):
        self.am.init_app(flask.current_app)
        assert not m_init.called

    @mock.patch('keg_auth.core.AuthManager.init_model')
    def test_authenticators_initialized(self, m_model):
        app = mock.MagicMock()
        manager = AuthManager(None, secondary_authenticators=[JwtAuthenticator])
        manager.init_app(app)
        assert isinstance(manager.primary_authenticator, KegAuthenticator)
        assert isinstance(manager.get_authenticator('jwt'), JwtAuthenticator)
        assert manager.primary_authenticator is manager.get_authenticator('keg')
