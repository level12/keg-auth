import datetime as dt

import arrow
import flask
import keg
from keg_elements.forms import Form, ModelForm, FieldMeta, MultiCheckboxField
from keg_elements.forms.validators import ValidateUnique
from sqlalchemy.sql.functions import coalesce
from sqlalchemy_utils import EmailType
from wtforms.fields import (
    BooleanField,
    DateField,
    HiddenField,
    PasswordField,
    StringField,
    SelectMultipleField)
from wtforms import ValidationError, validators
from wtforms_components.widgets import EmailInput

from keg_auth.extensions import lazy_gettext as _
from keg_auth.libs import get_domain_from_email
from keg_auth.libs.templates import link_to
from keg_auth.model import get_username_key


def login_form():
    """Returns a Login form class that handles username options."""
    login_id_label = _(u'User ID')
    login_id_validators = [validators.DataRequired()]

    if isinstance(flask.current_app.auth_manager.entity_registry.user_cls.username.type, EmailType):
        login_id_label = _(u'Email')
        login_id_validators.append(validators.Email())

    class Login(Form):
        next = HiddenField()

        login_id = StringField(login_id_label, validators=login_id_validators)
        password = PasswordField(_('Password'), validators=[
            validators.DataRequired(),
        ])

    return Login


class ForgotPassword(Form):
    """Returns a form to capture email for password reset."""
    email = StringField(_(u'Email'), validators=[
        validators.DataRequired(),
        validators.Email(),
    ])


class SetPassword(Form):
    """Returns a form to capture password/confirmation and apply password policy."""
    password = PasswordField(_('New Password'), validators=[
        validators.DataRequired(),
        validators.EqualTo('confirm', message=_('Passwords must match'))
    ])
    confirm = PasswordField(_('Confirm Password'))

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        super().__init__(*args, **kwargs)

        auth_manager = keg.current_app.auth_manager
        password_policy = auth_manager.password_policy_cls()
        self.password.validators = [*self.password.validators, *password_policy.form_validators()]


def get_permission_options():
    perm_cls = flask.current_app.auth_manager.entity_registry.permission_cls
    query = perm_cls.query.with_entities(
        perm_cls.id, coalesce(perm_cls.description, perm_cls.token).label('desc')
    ).order_by('desc').all()
    return [(str(perm.id), perm.desc) for perm in query]


def get_bundle_options():
    bundle_cls = flask.current_app.auth_manager.entity_registry.bundle_cls
    return [(str(bundle.id), bundle.name) for bundle in bundle_cls.query.order_by('name')]


def get_group_options():
    group_cls = flask.current_app.auth_manager.entity_registry.group_cls
    return [(str(group.id), group.name) for group in group_cls.query.order_by('name')]


def entities_from_ids(cls, ids):
    if not ids:
        return []
    return cls.query.filter(cls.id.in_(ids)).all()


class GroupsMixin(object):
    group_ids = SelectMultipleField('Groups')

    def after_init(self, args, kwargs):
        self.group_ids.choices = get_group_options()
        if kwargs.get('obj') and self.group_ids.raw_data is None:
            self.group_ids.process_data([group.id for group in kwargs['obj'].groups])
        super().after_init(args, kwargs)

    def get_selected_groups(self):
        return entities_from_ids(flask.current_app.auth_manager.entity_registry.group_cls,
                                 self.group_ids.data)


class PermissionsMixin(object):
    permission_ids = MultiCheckboxField(
        'Permissions',
        render_kw={'class': 'list-unstyled'},
    )

    def after_init(self, args, kwargs):
        self.permission_ids.choices = get_permission_options()
        if kwargs.get('obj') and self.permission_ids.raw_data is None:
            self.permission_ids.process_data([perm.id for perm in kwargs['obj'].permissions])
        super().after_init(args, kwargs)

    def get_selected_permissions(self):
        selected_ids = self.permission_ids.data
        return entities_from_ids(flask.current_app.auth_manager.entity_registry.permission_cls,
                                 selected_ids)


class BundlesMixin(object):
    bundle_ids = SelectMultipleField('Bundles')

    def after_init(self, args, kwargs):
        self.bundle_ids.choices = get_bundle_options()
        if kwargs.get('obj') and self.bundle_ids.raw_data is None:
            self.bundle_ids.process_data([bundle.id for bundle in kwargs['obj'].bundles])
        super().after_init(args, kwargs)

    def get_selected_bundles(self):
        return entities_from_ids(flask.current_app.auth_manager.entity_registry.bundle_cls,
                                 self.bundle_ids.data)


class _ValidatePasswordRequired(object):
    def __call__(self, form, field):
        if not form.obj and not field.data:
            raise ValidationError(_('This field is required.'))
        return True


class _ValidateUsername:
    def __init__(self, username_key=None):
        self.username_key = username_key

    def __call__(self, form, field):
        if form.obj and getattr(form.obj, self.username_key) != field.data:
            original_domain = get_domain_from_email(getattr(form.obj, self.username_key))
            new_domain = get_domain_from_email(field.data)
            is_exclusion = flask.current_app.auth_manager.login_authenticator.is_domain_excluded(
                getattr(form.obj, self.username_key)
            )
            if original_domain and is_exclusion and original_domain != new_domain:
                raise ValidationError(_('Cannot change user domain.'))
        return True


def user_form(config=None, allow_superuser=False, endpoint='',
              fields=['is_enabled', 'disabled_utc']):
    """Returns a form for User CRUD.

    Form is customized depending on the fields and superuser setting passed in."""
    config = config or {}
    user_cls = flask.current_app.auth_manager.entity_registry.user_cls

    # The model can be assumed to have a `username` attribute. However, it may not be settable,
    # depending on whether it is actually a column, or is instead a proxy to another column
    # (e.g. email). So, we will need to grab a key to use for it that matches the data column.
    username_key = get_username_key(flask.current_app.auth_manager.entity_registry.user_cls)

    # create a copy of fields for internal use. In python 2, if we use this as a static method,
    #   the kwarg value would get modified in the wrong scope
    _fields = [username_key] + fields[:]
    if allow_superuser and 'is_superuser' not in _fields:
        _fields.append('is_superuser')

    def html_link(obj):
        return link_to(
            obj.username,
            flask.url_for(endpoint, objid=obj.id)
        )

    def filter_disabled_utc(date):
        if isinstance(date, dt.date):
            date = arrow.get(date)

        return date

    class User(PermissionsMixin, BundlesMixin, GroupsMixin, ModelForm):
        if 'disabled_utc' in _fields:
            disabled_utc = DateField('Disable Date', [validators.Optional()],
                                     filters=[filter_disabled_utc], render_kw={'type': 'date'})

        class Meta:
            model = user_cls
            only = _fields

        class FieldsMeta:
            is_enabled = FieldMeta('Enabled')
            is_superuser = FieldMeta('Superuser')
            __default__ = FieldMeta

        _field_order = tuple(_fields + ['group_ids', 'bundle_ids',
                                        'permission_ids'])

        setattr(FieldsMeta, username_key, FieldMeta(
            extra_validators=[validators.data_required(),
                              ValidateUnique(html_link),
                              _ValidateUsername(username_key)]
        ))

        if isinstance(flask.current_app.auth_manager.entity_registry.user_cls.username.type,
                      EmailType):
            getattr(FieldsMeta, username_key).widget = EmailInput()

        if not config.get('KEGAUTH_EMAIL_OPS_ENABLED'):
            reset_password = PasswordField(_('New Password'), validators=[
                _ValidatePasswordRequired(),
                validators.EqualTo('confirm', message=_('Passwords must match'))
            ])
            confirm = PasswordField(_('Confirm Password'))
            _field_order = _field_order + ('reset_password', 'confirm')
        else:
            # place a Send Welcome field after the initial set of fields
            send_welcome = BooleanField('Send Welcome Email', default=True)
            _field_order = tuple(_fields + ['send_welcome'] + list(_field_order[len(_fields):]))

        def get_object_by_field(self, field):
            return user_cls.get_by(username=field.data)

        @property
        def obj(self):
            return self._obj

        def after_init(self, args, kwargs):
            if kwargs.get('obj') and hasattr(self, 'send_welcome'):
                self.send_welcome = None
                del self._fields['send_welcome']
                self._field_order = tuple(filter(lambda v: v != 'send_welcome', self._field_order))

            return super().after_init(args, kwargs)

    return User


def group_form(endpoint):
    """Returns a form for Group CRUD."""
    group_cls = flask.current_app.auth_manager.entity_registry.group_cls

    def html_link(obj):
        import flask
        return link_to(obj.name, flask.url_for(endpoint, objid=obj.id))

    class Group(PermissionsMixin, BundlesMixin, ModelForm):
        _field_order = ('name', 'bundle_ids', 'permission_ids',)

        class Meta:
            model = group_cls

        class FieldsMeta:
            name = FieldMeta(extra_validators=[ValidateUnique(html_link)])

        def get_object_by_field(self, field):
            return group_cls.get_by(name=field.data)

        @property
        def obj(self):
            return self._obj

    return Group


def bundle_form(endpoint):
    """Returns a form for Bundle CRUD."""
    bundle_cls = flask.current_app.auth_manager.entity_registry.bundle_cls

    def html_link(obj):
        import flask
        return link_to(obj.name, flask.url_for(endpoint, objid=obj.id))

    class Bundle(PermissionsMixin, ModelForm):
        class Meta:
            model = bundle_cls

        class FieldsMeta:
            name = FieldMeta(extra_validators=[ValidateUnique(html_link)])

        def get_object_by_field(self, field):
            return bundle_cls.get_by(name=field.data)

        @property
        def obj(self):
            return self._obj

    return Bundle
