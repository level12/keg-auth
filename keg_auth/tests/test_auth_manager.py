import flask

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
