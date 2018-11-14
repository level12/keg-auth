from __future__ import unicode_literals

import flask
import mock
from keg_auth.core import AuthManager
from keg_auth.libs.authenticators import KegAuthenticator, JwtRequestLoader

from keg_auth_ta.app import mail_ext
from keg_auth_ta.extensions import auth_entity_registry
from keg_auth_ta.model import entities as ents


class TestAuthManager(object):
    def setup(self):
        ents.Permission.delete_cascaded()
        ents.User.delete_cascaded()
        self.am = flask.current_app.auth_manager

    def test_create_user(self):
        with mail_ext.record_messages() as outbox:
            user = self.am.create_user(dict(email=u'foo@bar.com'))

        assert len(outbox) == 1
        assert outbox[0].subject == '[KA Demo] User Welcome & Verification'

        assert user.email == 'foo@bar.com'
        assert user._token_plain
        assert ents.User.query.count() == 1

    def test_create_user_no_commit(self):
        self.am.create_user(dict(email=u'foo@bar.com'), _commit=False)
        ents.db.session.rollback()
        assert ents.User.query.count() == 0

    def test_create_user_commit(self):
        self.am.create_user(dict(email=u'foo@bar.com'), _commit=True)
        ents.db.session.rollback()
        assert ents.User.query.count() == 1

    @mock.patch('keg_auth.core.model.initialize_mappings')
    def test_model_initialized_only_once(self, m_init):
        self.am.init_app(flask.current_app)
        assert not m_init.called

    def test_permissions_synced_to_db(self):
        # create a permission that will get destroyed by sync, and ensure no integrity errors
        permission_to_delete = ents.Permission.add(token='snoopy')
        ents.Group.testing_create(permissions=[permission_to_delete])
        ents.Bundle.testing_create(permissions=[permission_to_delete])
        ents.User.testing_create(permissions=[permission_to_delete])

        # token should not be duplicated during sync, but description should be set
        ents.Permission.add(token='bar')

        # define the app permissions
        permissions = (
            'foo',
            ('bar', 'location for libations'),
            ('baz', 'nonsense word'),
        )
        with mock.patch.object(self.am, 'permissions', permissions):
            # we want to make sure the sync will still
            # run when mode is not testing
            flask.current_app.config['TESTING'] = False
            self.am.init_app(flask.current_app)

        assert ents.Permission.get_by(token='foo')
        assert ents.Permission.get_by(token='bar').description == 'location for libations'
        assert ents.Permission.get_by(token='baz').description == 'nonsense word'
        assert not ents.Permission.get_by(token='snoopy')
        flask.current_app.config['TESTING'] = True

    @mock.patch('keg_auth.core.KegAuthenticator')
    def test_request_loaders_initialized_only_once(self, m_init):
        self.am.init_app(flask.current_app)
        assert not m_init.called

    @mock.patch('keg_auth.core.AuthManager.init_model')
    def test_request_loaders_initialized(self, m_model):
        app = mock.MagicMock()
        manager = AuthManager(None, request_loaders=[JwtRequestLoader],
                              entity_registry=auth_entity_registry)
        manager.init_app(app)
        assert isinstance(manager.login_authenticator, KegAuthenticator)
        assert isinstance(manager.get_request_loader('jwt'), JwtRequestLoader)

    def test_resend_verification(self):
        user = ents.User.testing_create(
            email='foo1@bar.com'
        )
        with mail_ext.record_messages() as outbox:
            self.am.resend_verification_email(user.id)

        assert len(outbox) == 1
        assert outbox[0].subject == '[KA Demo] User Welcome & Verification'
