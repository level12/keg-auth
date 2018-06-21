from keg_elements.forms import Form, ModelForm, FieldMeta
from keg_elements.forms.validators import ValidateUnique
from webhelpers2.html.tags import link_to
from wtforms.fields import (
    HiddenField,
    PasswordField,
    StringField,
    SelectMultipleField)
from wtforms import validators
from wtforms_components import EmailField

from keg_auth.model import entity_registry


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


class SetPassword(Form):
    password = PasswordField('New Password', validators=[
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Confirm Password')


def get_permission_options():
    perm_cls = entity_registry.registry.permission_cls
    return [(str(perm.id), perm.description) for perm in perm_cls.query.order_by('description')]


def get_bundle_options():
    bundle_cls = entity_registry.registry.bundle_cls
    return [(str(bundle.id), bundle.name) for bundle in bundle_cls.query.order_by('name')]


def get_group_options():
    group_cls = entity_registry.registry.group_cls
    return [(str(group.id), group.name) for group in group_cls.query.order_by('name')]


def entities_from_ids(cls, ids):
    if not ids:
        return []
    return cls.query.filter(cls.id.in_(ids)).all()


class PermissionsMixin(object):
    permission_ids = SelectMultipleField('Permissions')

    def get_selected_permissions(self):
        return entities_from_ids(entity_registry.registry.permission_cls, self.permission_ids.data)


class BundlesMixin(object):
    bundle_ids = SelectMultipleField('Bundles')

    def get_selected_bundles(self):
        return entities_from_ids(entity_registry.registry.bundle_cls, self.bundle_ids.data)


def user_form(allow_superuser, endpoint):
    user_cls = entity_registry.registry.user_cls

    fields = ['email', 'is_enabled']
    if allow_superuser:
        fields.append('is_superuser')

    def html_link(obj):
        import flask
        return link_to(obj.email, flask.url_for(endpoint, objid=obj.id))

    class User(ModelForm, PermissionsMixin, BundlesMixin):
        class Meta:
            model = user_cls
            only = fields

        class FieldsMeta:
            is_enabled = FieldMeta('Enabled')
            is_superuser = FieldMeta('Superuser')
            __default__ = FieldMeta

        email = EmailField('Email', validators=[validators.data_required(),
                                                validators.email(),
                                                ValidateUnique(html_link)])

        group_ids = SelectMultipleField('Groups')

        def after_init(self, args, kwargs):
            self.permission_ids.choices = get_permission_options()
            self.bundle_ids.choices = get_bundle_options()
            self.group_ids.choices = get_group_options()

        def get_selected_groups(self):
            return entities_from_ids(entity_registry.registry.group_cls, self.group_ids.data)

        def get_object_by_field(self, field):
            return user_cls.get_by(email=field.data)

        @property
        def obj(self):
            return self._obj

        __order = tuple(fields + ['group_ids', 'bundle_ids', 'permission_ids'])

        def __iter__(self):
            order = ('csrf_token', ) + self.__order
            return (getattr(self, field_id) for field_id in order)

    return User


def group_form(endpoint):
    group_cls = entity_registry.registry.group_cls

    def html_link(obj):
        import flask
        return link_to(obj.email, flask.url_for(endpoint, objid=obj.id))

    class Group(ModelForm, PermissionsMixin, BundlesMixin):
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
    bundle_cls = entity_registry.registry.bundle_cls

    def html_link(obj):
        import flask
        return link_to(obj.email, flask.url_for(endpoint, objid=obj.id))

    class Bundle(ModelForm, PermissionsMixin):
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
