from collections import namedtuple

from blazeutils.strings import normalizews
import CommonMark as commonmark
import flask
import flask_mail
import markupsafe

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


class MailManager:
    reset_password_templates = ('mail/reset-password.j2', 'kegauth/reset-password-mail.j2')

    def __init__(self, mail_ext):
        self.mail_ext = mail_ext

    def reset_password_message(self, user):
        parts = mail_template(self.reset_password_templates, user=user)

        return flask_mail.Message(parts.subject, [user.email], parts.text, parts.html)

    def send_reset_password(self, user):
        msg = self.reset_password_message(user)
        self.mail_ext.send(msg)
