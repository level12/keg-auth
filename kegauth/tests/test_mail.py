import flask
from kegauth import mail
import mock

from kegauth_ta.app import mail_ext
from kegauth_ta.model import entities as ents


class TestMailTemplate:

    def test_normal(self):
        email = mail.mail_template('email.j2', name='foo')
        assert email.subject == '[KA Demo] Example Subject'
        assert email.text == '**Hello foo**'
        assert email.html == '<p><strong>Hello foo</strong></p>\n'

    def test_no_abbr(self):
        with mock.patch.dict(flask.current_app.config, KEGAUTH_EMAIL_SITE_ABBR=None):
            email = mail.mail_template('email.j2')
        assert email.subject == 'Example Subject'


class TestMailManager:
    @classmethod
    def setup_class(cls):
        cls.mb = mail.MailManager(mail_ext)

    def test_reset_password_message(self):
        user = ents.User.testing_create(email='foo@bar.com')
        user.token_generate()

        with flask.current_app.test_request_context():
            message = self.mb.reset_password_message(user)

        assert message.subject == '[KA Demo] Password Reset Link'
        assert message.recipients == ['foo@bar.com']
        assert 'Somebody asked to reset your password on Keg Auth Demo.' in message.body
        reset_url = 'http://keg.example.com/reset-password/{}/{}'.format(user.id, user._token_plain)
        assert '<{}>'.format(reset_url) in message.body
        assert 'href="{}"'.format(reset_url) in message.html

    def test_send_reset_password(self):
        user = ents.User.testing_create()

        with mail_ext.record_messages() as outbox:
            flask.current_app.auth_mail_manager.send_reset_password(user)

            assert len(outbox) == 1
            assert outbox[0].subject == '[KA Demo] Password Reset Link'
