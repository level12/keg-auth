from flask import current_app
from mock import mock
from pyquery import PyQuery
from werkzeug.datastructures import MultiDict

from keg_auth import forms
import keg_auth_ta.model.entities as ents


class FormBase(object):
    form_cls = None

    def ok_data(self, **kwargs):
        return kwargs

    def make_form(self, **kwargs):
        obj = kwargs.pop('obj', None)
        data = MultiDict(self.ok_data(**kwargs))
        return self.form_cls(data, obj=obj)

    def assert_valid(self, **kwargs):
        form = self.make_form(**kwargs)
        assert form.validate()
        return form

    def assert_not_valid(self, **kwargs):
        form = self.make_form(**kwargs)
        assert not form.validate()
        return form

    def test_ok(self):
        self.assert_valid()


@mock.patch.dict(current_app.config, WTF_CSRF_ENABLED=False)
class TestLogin(FormBase):
    form_cls = forms.Login

    def ok_data(self, **kwargs):
        return {
            'email': 'foo@example.com',
            'password': 'password123',
            **kwargs
        }

    def test_required(self):
        form = self.assert_not_valid(email='', password='')
        msg = ['This field is required.']
        assert form.email.errors == msg
        assert form.password.errors == msg

    def test_valid_email(self):
        form = self.assert_not_valid(email='foo')
        assert form.email.errors == ['Invalid email address.']


@mock.patch.dict(current_app.config, WTF_CSRF_ENABLED=False)
class TestForgotPassword(FormBase):
    form_cls = forms.ForgotPassword

    def ok_data(self, **kwargs):
        return {
            'email': 'foo@example.com',
            **kwargs
        }

    def test_required(self):
        form = self.assert_not_valid(email='')
        msg = ['This field is required.']
        assert form.email.errors == msg

    def test_valid_email(self):
        form = self.assert_not_valid(email='foo')
        assert form.email.errors == ['Invalid email address.']


@mock.patch.dict(current_app.config, WTF_CSRF_ENABLED=False)
class TestSetPassword(FormBase):
    form_cls = forms.SetPassword

    def ok_data(self, **kwargs):
        return {
            'password': 'password123',
            'confirm': 'password123',
            **kwargs
        }

    def test_required(self):
        form = self.assert_not_valid(password='')
        assert form.password.errors == ['This field is required.']

    def test_valid_confirm(self):
        form = self.assert_not_valid(confirm='password1234')
        assert form.password.errors == ['Passwords must match']


@mock.patch.dict(current_app.config, WTF_CSRF_ENABLED=False)
class TestUser(FormBase):
    form_cls = forms.user_form(False, endpoint='auth.user:edit')

    @classmethod
    def setup_class(cls):
        ents.Permission.delete_cascaded()
        ents.Group.delete_cascaded()
        ents.Bundle.delete_cascaded()

        cls.perms = [ents.Permission.testing_create() for _ in range(3)]
        cls.groups = [ents.Group.testing_create() for _ in range(3)]
        cls.bundles = [ents.Bundle.testing_create() for _ in range(3)]

    def setup(self):
        ents.User.delete_cascaded()

    def ok_data(self, **kwargs):
        return {
            'email': 'foo@example.com',
            'is_enabled': 'true',
            'permission_ids': [str(self.perms[0].id), str(self.perms[1].id)],
            'group_ids': [str(self.groups[0].id), str(self.groups[1].id)],
            'bundle_ids': [str(self.bundles[0].id), str(self.bundles[1].id)],
            **kwargs
        }

    def test_required(self):
        form = self.assert_not_valid(email='')
        assert form.email.errors == ['This field is required.']

    def test_valid_email(self):
        form = self.assert_not_valid(email='foo')
        assert form.email.errors == ['Invalid email address.']

    def test_superuser_available(self):
        form = self.make_form()
        assert not hasattr(form, 'is_superuser')

        form = forms.user_form(True, endpoint='auth.user:edit')
        assert hasattr(form, 'is_superuser')

    def test_multi_select(self):
        form = self.assert_valid()
        assert form.get_selected_permissions() == self.perms[:2]
        assert form.get_selected_groups() == self.groups[:2]
        assert form.get_selected_bundles() == self.bundles[:2]

        form = self.assert_valid(permission_ids=[], group_ids=[], bundle_ids=[])
        assert form.get_selected_permissions() == []
        assert form.get_selected_groups() == []
        assert form.get_selected_bundles() == []

    def test_unique(self):
        usr = ents.User.testing_create(email='foo@example.com')

        form = self.assert_not_valid()
        print(form.email.errors[0])
        error = PyQuery(form.email.errors[0])
        assert 'This value must be unique' in error.text()
        assert error('a').attr('href').endswith('/users/{}'.format(usr.id))
        assert error('a').text() == 'foo@example.com'

        self.assert_valid(obj=usr)


@mock.patch.dict(current_app.config, WTF_CSRF_ENABLED=False)
class TestGroup(FormBase):
    form_cls = forms.group_form(endpoint='auth.group:edit')

    @classmethod
    def setup_class(cls):
        ents.Permission.delete_cascaded()
        ents.Bundle.delete_cascaded()

        cls.perms = [ents.Permission.testing_create() for _ in range(3)]
        cls.bundles = [ents.Bundle.testing_create() for _ in range(3)]

    def ok_data(self, **kwargs):
        return {
            'name': 'some-group',
            'permission_ids': [str(self.perms[0].id), str(self.perms[1].id)],
            'bundle_ids': [str(self.bundles[0].id), str(self.bundles[1].id)],
            **kwargs
        }

    def test_required(self):
        form = self.assert_not_valid(name='')
        assert form.name.errors == ['This field is required.']

    def test_multi_select(self):
        form = self.assert_valid()
        assert form.get_selected_permissions() == self.perms[:2]
        assert form.get_selected_bundles() == self.bundles[:2]

        form = self.assert_valid(permission_ids=[], bundle_ids=[])
        assert form.get_selected_permissions() == []
        assert form.get_selected_bundles() == []


@mock.patch.dict(current_app.config, WTF_CSRF_ENABLED=False)
class TestBundle(FormBase):
    form_cls = forms.bundle_form(endpoint='auth.bundle:edit')

    @classmethod
    def setup_class(cls):
        ents.Permission.delete_cascaded()

        cls.perms = [ents.Permission.testing_create() for _ in range(3)]

    def ok_data(self, **kwargs):
        return {
            'name': 'some-bundle',
            'permission_ids': [str(self.perms[0].id), str(self.perms[1].id)],
            **kwargs
        }

    def test_required(self):
        form = self.assert_not_valid(name='')
        assert form.name.errors == ['This field is required.']

    def test_multi_select(self):
        form = self.assert_valid()
        assert form.get_selected_permissions() == self.perms[:2]

        form = self.assert_valid(permission_ids=[])
        assert form.get_selected_permissions() == []
