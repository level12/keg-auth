from collections import namedtuple

from blazeutils.strings import normalizews
import commonmark
import flask

try:
    import flask_mail
except ImportError:
    pass

MailParts = namedtuple('MailParts', 'subject text html')


def mail_template(template_name_or_list, **kwargs):
    multi_part_content = flask.render_template(template_name_or_list, **kwargs)
    parts = multi_part_content.split('---multi-part:xFE+Ab7j+w,mdIL%---')
    subject, markdown = map(lambda p: p.strip(), parts)

    return MailParts(
        normalizews(subject),
        markdown,
        commonmark.commonmark(markdown)
    )


class AuthMailManager(object):
    reset_password_templates = ('mail/reset-password.j2', 'keg_auth/reset-password-mail.j2')
    new_user_templates = ('mail/new-user.j2', 'keg_auth/new-user-mail.j2')

    def __init__(self, mail_ext):
        self.mail_ext = mail_ext

    def reset_password_message(self, user):
        parts = mail_template(self.reset_password_templates, user=user)

        return flask_mail.Message(parts.subject, [user.email], parts.text, parts.html)

    def send_reset_password(self, user):
        msg = self.reset_password_message(user)
        self.mail_ext.send(msg)

    def new_user_message(self, user):
        parts = mail_template(self.new_user_templates, user=user)

        return flask_mail.Message(parts.subject, [user.email], parts.text, parts.html)

    def send_new_user(self, user):
        msg = self.new_user_message(user)
        self.mail_ext.send(msg)

    def verify_account_url(self, user):
        return flask.current_app.auth_manager.url_for(
            'verify-account', user_id=user.id, token=user._token_plain, _external=True)

    def reset_password_url(self, user):
        return flask.current_app.auth_manager.url_for(
            'reset-password', user_id=user.id, token=user._token_plain, _external=True)
