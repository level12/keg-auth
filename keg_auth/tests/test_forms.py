from blazeutils.strings import randchars
import pytest
from flask import current_app
from mock import mock
from pyquery import PyQuery
from werkzeug.datastructures import MultiDict

from keg_auth import forms
import keg_auth_ta.model.entities as ents
from keg_auth.libs.authenticators import PasswordPolicy


class FormBase(object):
    form_cls = None

    def ok_data(self, **kwargs):
        return kwargs

    def make_form(self, **kwargs):
        form_cls = kwargs.pop('form_cls', None) or self.form_cls
        obj = kwargs.pop('obj', None)
        data = MultiDict(self.ok_data(**kwargs))
        return form_cls(data, obj=obj)

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
    form_cls = forms.login_form()

    def ok_data(self, **kwargs):
        data = {
            'login_id': 'foo@example.com',
            'password': 'password123',
        }
        data.update(kwargs)
        return data

    def test_required(self):
        form = self.assert_not_valid(login_id='', password='')
        msg = ['This field is required.']
        assert form.login_id.errors == msg
        assert form.password.errors == msg

    def test_valid_email(self):
        form = self.assert_not_valid(login_id='foo')
        assert form.login_id.errors == ['Invalid email address.']
        assert form.login_id.label.text == 'Email'

    def test_no_email_validation(self):
        with mock.patch('keg_auth_ta.extensions.auth_entity_registry._user_cls', ents.UserNoEmail):
            form_cls = forms.login_form()
            form = self.assert_valid(form_cls=form_cls, login_id='foo')
            assert form.login_id.label.text == 'User ID'


@mock.patch.dict(current_app.config, WTF_CSRF_ENABLED=False)
class TestForgotPassword(FormBase):
    form_cls = forms.ForgotPassword

    def ok_data(self, **kwargs):
        data = {
            'email': 'foo@example.com',
        }
        data.update(kwargs)
        return data

    def test_required(self):
        form = self.assert_not_valid(email='')
        msg = ['This field is required.']
        assert form.email.errors == msg

    def test_valid_email(self):
        form = self.assert_not_valid(email='foo')
        assert form.email.errors == ['Invalid email address.']


@mock.patch.dict(current_app.config, WTF_CSRF_ENABLED=False)
@mock.patch.object(current_app.auth_manager, 'password_policy_cls', new=PasswordPolicy)
class TestSetPassword(FormBase):
    def setup_method(self, _):
        ents.User.delete_cascaded()
        self.user = ents.User.fake()

    def ok_data(self, **kwargs):
        data = {
            'password': 'password123!',
            'confirm': 'password123!',
        }
        data.update(kwargs)
        return data

    def form_cls(self, *args, **kwargs):
        kwargs.setdefault('user', self.user)
        return forms.SetPassword(*args, **kwargs)

    def test_required(self):
        form = self.assert_not_valid(password='')
        assert form.password.errors == ['This field is required.']

    def test_valid_confirm(self):
        form = self.assert_not_valid(confirm='password1234')
        assert form.password.errors == ['Passwords must match']

    def test_length_validator(self):
        form = self.assert_not_valid(password='aBcDe1!', confirm='aBcDe1!')
        assert form.password.errors == ['Password must be at least 8 characters long']

        self.assert_valid(password='aBcDeF1!', confirm='aBcDeF1!')

    @pytest.mark.parametrize('pw', [
        'a' * 10,
        'A' * 10,
        '1' * 10,
        'aA' * 5,
        'a1' * 5,
        '1!' * 5,
    ])
    def test_char_set_validator_failures(self, pw):
        form = self.assert_not_valid(password=pw, confirm=pw)
        assert form.password.errors == [
            'Password must include at least 3 of lowercase letter, uppercase letter, number and/or symbol'  # noqa: E501
        ]

    @pytest.mark.parametrize('pw', [
        'aaaaaaaa1!',
        'aaaaaaaaA!',
        'aaaaaaaaA1',
        'AAAAAAAA1!',
    ])
    def test_char_set_validator_pass(self, pw):
        self.assert_valid(password=pw, confirm=pw)

    @pytest.mark.parametrize('pw,email', [
        ('1!bob!1234', 'bob@example.com'),
        ('BoB123456!', 'bOb@example.com'),
    ])
    def test_username_validator_failures(self, pw, email):
        self.user.email = email
        form = self.assert_not_valid(password=pw, confirm=pw)
        assert form.password.errors == ['Password may not contain username']

    @pytest.mark.parametrize('pw,email', [
        ('1!b0b!1234', 'bob@example.com'),
        ('B0B123456!', 'bOb@example.com'),
    ])
    def test_username_validator_pass(self, pw, email):
        self.user.email = email
        self.assert_valid(password=pw, confirm=pw)


@mock.patch.dict(current_app.config, WTF_CSRF_ENABLED=False)
class TestUser(FormBase):
    form_cls = forms.user_form({'KEGAUTH_EMAIL_OPS_ENABLED': True},
                               allow_superuser=False, endpoint='auth.user:edit')

    @classmethod
    def setup_class(cls):
        ents.Permission.delete_cascaded()
        ents.Group.delete_cascaded()
        ents.Bundle.delete_cascaded()

        cls.perms = [ents.Permission.fake() for _ in range(3)]
        cls.groups = [ents.Group.fake() for _ in range(3)]
        cls.bundles = [ents.Bundle.fake() for _ in range(3)]

    def setup_method(self):
        ents.User.delete_cascaded()

    def ok_data(self, **kwargs):
        data = {
            'email': 'foo@example.com',
            'is_enabled': 'true',
            'disabled_utc': '2019-01-01',
            'permission_ids': [str(self.perms[0].id), str(self.perms[1].id)],
            'group_ids': [str(self.groups[0].id), str(self.groups[1].id)],
            'bundle_ids': [str(self.bundles[0].id), str(self.bundles[1].id)],
        }
        data.update(kwargs)
        return data

    def test_required(self):
        form = self.assert_not_valid(email='')
        assert form.email.errors == ['This field is required.']

    def test_valid_email(self):
        form = self.assert_not_valid(email='foo')
        assert form.email.errors == ['Invalid email address.']

    def test_superuser_available(self):
        form = self.make_form()
        assert not hasattr(form, 'is_superuser')

        form = forms.user_form({'KEGAUTH_EMAIL_OPS_ENABLED': True},
                               allow_superuser=True, endpoint='auth.user:edit')
        assert hasattr(form, 'is_superuser')

    def test_alternate_ident_field(self):
        with mock.patch('keg_auth_ta.extensions.auth_entity_registry._user_cls', ents.UserNoEmail):
            form_cls = forms.user_form({'KEGAUTH_EMAIL_OPS_ENABLED': True},
                                       allow_superuser=False, endpoint='auth.user:edit')
            assert hasattr(form_cls, 'username')

    def test_send_welcome_present(self):
        form = self.make_form()
        assert form.send_welcome
        assert 'send_welcome' in form._fields

    def test_send_welcome_absent(self):
        user = ents.User.fake()
        form = self.make_form(obj=user)
        assert not form.send_welcome
        assert 'send_welcome' not in form._fields

    def test_no_email(self):
        with mock.patch('keg_auth_ta.extensions.auth_entity_registry._user_cls', ents.UserNoEmail):
            form_cls = forms.user_form({'KEGAUTH_EMAIL_OPS_ENABLED': False},
                                       allow_superuser=False, endpoint='auth.user:edit')
            assert hasattr(form_cls, 'username')
            assert not hasattr(form_cls, 'email')
            assert hasattr(form_cls, 'reset_password')
            assert hasattr(form_cls, 'confirm')

            form = self.assert_not_valid(form_cls=form_cls, reset_password='xyz', confirm='abc')
            assert form.reset_password.errors == ['Passwords must match']
            self.assert_valid(form_cls=form_cls, username='foobar', reset_password='xyz',
                              confirm='xyz')

    def test_multi_select(self):
        form = self.assert_valid()
        assert form.get_selected_permissions() == self.perms[:2]
        assert form.get_selected_groups() == self.groups[:2]
        assert form.get_selected_bundles() == self.bundles[:2]

        form = self.assert_valid(permission_ids=[], group_ids=[], bundle_ids=[])
        assert form.get_selected_permissions() == []
        assert form.get_selected_groups() == []
        assert form.get_selected_bundles() == []

    def test_domain_lock(self):
        with mock.patch(
            'flask.current_app.auth_manager.login_authenticator.domain_exclusions',
            ['example.com']
        ):
            self.assert_valid()
            usr = ents.User.fake(email='foo@example.com')
            self.assert_valid(obj=usr)
            self.assert_valid(obj=usr, email='bar@example.com')
            form = self.assert_not_valid(obj=usr, email='bar@otherdomain.biz')
            assert form.email.errors == ['Cannot change user domain.']

        self.assert_valid(obj=usr, email='bar@otherdomain.biz')

    def test_unique(self):
        usr = ents.User.fake(email='foo@example.com')

        form = self.assert_not_valid()
        error = PyQuery(form.email.errors[1])
        assert 'This value must be unique' in error.text()
        assert error('a').attr('href').endswith('/users/{}/edit'.format(usr.id))
        assert error('a').text() == 'foo@example.com'

        self.assert_valid(obj=usr)

    def test_unique_alternate_ident_field(self):
        with mock.patch('keg_auth_ta.extensions.auth_entity_registry._user_cls', ents.UserNoEmail):
            form_cls = forms.user_form({'KEGAUTH_EMAIL_OPS_ENABLED': True},
                                       allow_superuser=False, endpoint='auth.user:edit')
            usr = ents.UserNoEmail.fake(username='foobar')

            form = self.assert_not_valid(form_cls=form_cls, username='foobar')
            error = PyQuery(form.username.errors[1])
            assert 'This value must be unique' in error.text()
            assert error('a').attr('href').endswith('/users/{}/edit'.format(usr.id))
            assert error('a').text() == 'foobar'

            self.assert_valid(form_cls=form_cls, obj=usr, username='foobar')

    def test_fields_excluded(self):
        form_cls = forms.user_form(
            {'KEGAUTH_EMAIL_OPS_ENABLED': True},
            allow_superuser=False,
            endpoint='auth.user:edit',
            # exclude the default fields, to make sure we don't get field order errors
            fields=[],
        )
        form = form_cls()
        [field for field in form]


@mock.patch.dict(current_app.config, WTF_CSRF_ENABLED=False)
class TestGroup(FormBase):
    form_cls = forms.group_form(endpoint='auth.group:edit')

    @classmethod
    def setup_class(cls):
        ents.Permission.delete_cascaded()
        ents.Bundle.delete_cascaded()

        cls.perms = [ents.Permission.fake() for _ in range(3)]
        cls.bundles = [ents.Bundle.fake() for _ in range(3)]

    def ok_data(self, **kwargs):
        data = {
            'name': randchars(),
            'permission_ids': [str(self.perms[0].id), str(self.perms[1].id)],
            'bundle_ids': [str(self.bundles[0].id), str(self.bundles[1].id)],
        }
        data.update(kwargs)
        return data

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

    def test_unique(self):
        obj = ents.Group.fake(name='some-group')

        form = self.assert_not_valid(name='some-group')
        error = PyQuery(form.name.errors[0])
        assert 'Already exists.' in error.text()

        self.assert_valid(obj=obj)


@mock.patch.dict(current_app.config, WTF_CSRF_ENABLED=False)
class TestBundle(FormBase):
    form_cls = forms.bundle_form(endpoint='auth.bundle:edit')

    @classmethod
    def setup_class(cls):
        ents.Permission.delete_cascaded()

        cls.perms = [ents.Permission.fake() for _ in range(3)]

    def ok_data(self, **kwargs):
        data = {
            'name': randchars(),
            'permission_ids': [str(self.perms[0].id), str(self.perms[1].id)],
        }
        data.update(kwargs)
        return data

    def test_required(self):
        form = self.assert_not_valid(name='')
        assert form.name.errors == ['This field is required.']

    def test_multi_select(self):
        form = self.assert_valid()
        assert form.get_selected_permissions() == self.perms[:2]

        form = self.assert_valid(permission_ids=[])
        assert form.get_selected_permissions() == []

    def test_unique(self):
        obj = ents.Bundle.fake(name='some-bundle')

        form = self.assert_not_valid(name='some-bundle')
        error = PyQuery(form.name.errors[0])
        assert 'Already exists.' in error.text()

        self.assert_valid(obj=obj)
