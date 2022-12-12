import flask
from keg_auth import mail
import mock

from keg_auth_ta.app import mail_ext
from keg_auth_ta.model import entities as ents


class TestMailTemplate(object):

    def test_normal(self):
        email = mail.mail_template('email.j2', name='foo')
        assert email.subject == '[KA Demo] Example Subject'
        assert email.text == '**Hello foo**'
        assert email.html == '<p><strong>Hello foo</strong></p>\n'

    def test_no_abbr(self):
        with mock.patch.dict(flask.current_app.config, KEGAUTH_EMAIL_SITE_ABBR=None):
            email = mail.mail_template('email.j2')
        assert email.subject == 'Example Subject'


class TestAuthMailManager(object):
    @classmethod
    def setup_class(cls):
        cls.mb = mail.AuthMailManager(mail_ext)

    def setup_method(self):
        ents.User.delete_cascaded()

    def test_reset_password_message(self):
        user = ents.User.fake(email='foo@bar.com')
        user.token_generate()
        link_url = flask.current_app.auth_manager.mail_manager.reset_password_url(user)

        with flask.current_app.test_request_context():
            message = self.mb.reset_password_message(user)

        assert message.subject == '[KA Demo] Password Reset Link'
        assert message.recipients == ['foo@bar.com']
        assert 'Somebody asked to reset your password on Keg Auth Demo.' in message.body
        assert '<{}>'.format(link_url) in message.body
        assert 'href="{}"'.format(link_url) in message.html

    def test_send_reset_password(self):
        user = ents.User.fake()

        with mail_ext.record_messages() as outbox:
            flask.current_app.auth_manager.mail_manager.send_reset_password(user)

            assert len(outbox) == 1
            assert outbox[0].subject == '[KA Demo] Password Reset Link'

    def test_new_user_message(self):
        user = ents.User.fake(email='foo@bar.com')
        user.token_generate()
        link_url = flask.current_app.auth_manager.mail_manager.verify_account_url(user)

        with flask.current_app.test_request_context():
            message = self.mb.new_user_message(user)

        assert message.subject == '[KA Demo] User Welcome & Verification'
        assert message.recipients == ['foo@bar.com']
        assert 'A user account has been created for you on Keg Auth Demo.' in message.body
        assert '<{}>'.format(link_url) in message.body
        assert 'href="{}"'.format(link_url) in message.html

    def test_send_new_user(self):
        user = ents.User.fake()

        with mail_ext.record_messages() as outbox:
            flask.current_app.auth_manager.mail_manager.send_new_user(user)

            assert len(outbox) == 1
            assert outbox[0].subject == '[KA Demo] User Welcome & Verification'
