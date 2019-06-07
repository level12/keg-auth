import flask
from keg_elements.forms import Form, ModelForm, FieldMeta
from keg_elements.forms.validators import ValidateUnique
from sqlalchemy_utils import EmailType
from webhelpers2.html.tags import link_to
from wtforms.fields import (
    HiddenField,
    PasswordField,
    StringField,
    SelectMultipleField)
from wtforms import ValidationError, validators
from wtforms_components.widgets import EmailInput

from keg_auth.extensions import lazy_gettext as _
from keg_auth.model import get_username_key


def login_form():
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
    email = StringField(_(u'Email'), validators=[
        validators.DataRequired(),
        validators.Email(),
    ])


class SetPassword(Form):
    password = PasswordField(_('New Password'), validators=[
        validators.DataRequired(),
        validators.EqualTo('confirm', message=_('Passwords must match'))
    ])
    confirm = PasswordField(_('Confirm Password'))


def get_permission_options():
    perm_cls = flask.current_app.auth_manager.entity_registry.permission_cls
    return [(str(perm.id), perm.description) for perm in perm_cls.query.order_by('description')]


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


class PermissionsMixin(object):
    permission_ids = SelectMultipleField('Permissions')

    def get_selected_permissions(self):
        return entities_from_ids(flask.current_app.auth_manager.entity_registry.permission_cls,
                                 self.permission_ids.data)


class BundlesMixin(object):
    bundle_ids = SelectMultipleField('Bundles')

    def get_selected_bundles(self):
        return entities_from_ids(flask.current_app.auth_manager.entity_registry.bundle_cls,
                                 self.bundle_ids.data)


class _ValidatePasswordRequired(object):
    def __call__(self, form, field):
        if not form.obj and not field.data:
            raise ValidationError(_('This field is required.'))
        return True


def user_form(config=None, allow_superuser=False, endpoint='', fields=['is_enabled']):
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

    class User(PermissionsMixin, BundlesMixin, ModelForm):
        class Meta:
            model = user_cls
            only = _fields

        class FieldsMeta:
            is_enabled = FieldMeta('Enabled')
            is_superuser = FieldMeta('Superuser')
            __default__ = FieldMeta

        field_order = tuple(_fields + ['group_ids', 'bundle_ids', 'permission_ids'])

        setattr(FieldsMeta, username_key, FieldMeta(
            extra_validators=[validators.data_required(),
                              ValidateUnique(html_link)]
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
            field_order = field_order + ('reset_password', 'confirm')

        group_ids = SelectMultipleField(_('Groups'))

        def after_init(self, args, kwargs):
            self.permission_ids.choices = get_permission_options()
            self.bundle_ids.choices = get_bundle_options()
            self.group_ids.choices = get_group_options()

        def get_selected_groups(self):
            return entities_from_ids(flask.current_app.auth_manager.entity_registry.group_cls,
                                     self.group_ids.data)

        def get_object_by_field(self, field):
            return user_cls.get_by(username=field.data)

        @property
        def obj(self):
            return self._obj

        def __iter__(self):
            order = ('csrf_token', ) + self.field_order
            return (getattr(self, field_id) for field_id in order)

    return User


def group_form(endpoint):
    group_cls = flask.current_app.auth_manager.entity_registry.group_cls

    def html_link(obj):
        import flask
        return link_to(obj.name, flask.url_for(endpoint, objid=obj.id))

    class Group(PermissionsMixin, BundlesMixin, ModelForm):
        class Meta:
            model = group_cls

        class FieldsMeta:
            name = FieldMeta(extra_validators=[ValidateUnique(html_link)])

        def after_init(self, args, kwargs):
            self.permission_ids.choices = get_permission_options()
            self.bundle_ids.choices = get_bundle_options()

        def get_object_by_field(self, field):
            return group_cls.get_by(name=field.data)

        @property
        def obj(self):
            return self._obj

    return Group


def bundle_form(endpoint):
    bundle_cls = flask.current_app.auth_manager.entity_registry.bundle_cls

    def html_link(obj):
        import flask
        return link_to(obj.name, flask.url_for(endpoint, objid=obj.id))

    class Bundle(PermissionsMixin, ModelForm):
        class Meta:
            model = bundle_cls

        class FieldsMeta:
            name = FieldMeta(extra_validators=[ValidateUnique(html_link)])

        def after_init(self, args, kwargs):
            self.permission_ids.choices = get_permission_options()

        def get_object_by_field(self, field):
            return bundle_cls.get_by(name=field.data)

        @property
        def obj(self):
            return self._obj

    return Bundle
