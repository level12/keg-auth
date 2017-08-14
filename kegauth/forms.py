from keg_elements.forms import Form, form_validator
from wtforms.fields import (
    BooleanField,
    HiddenField,
    PasswordField,
    StringField,
)
from wtforms import validators


class Login(Form):
    next = HiddenField()

    email = StringField(u'Email', validators=[
        validators.DataRequired(),
        validators.Email(),
    ])
    password = PasswordField('Password', validators=[
        validators.DataRequired(),
    ])


class ForgotPassword(Form):
    email = StringField(u'Email', validators=[
        validators.DataRequired(),
        validators.Email(),
    ])


class ResetPassword(Form):
    password = PasswordField('New Password', validators=[
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Confirm Password')
