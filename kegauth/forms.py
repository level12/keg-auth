from keg_elements.forms import Form, form_validator
from wtforms.fields import (
    BooleanField,
    HiddenField,
    PasswordField,
    StringField,
)
from wtforms import validators


class LoginForm(Form):
    next = HiddenField()

    email = StringField(u'Email', validators=[
        validators.DataRequired(),
        validators.Email(),
    ])
    password = PasswordField('Password', validators=[
        validators.DataRequired(),
    ])
