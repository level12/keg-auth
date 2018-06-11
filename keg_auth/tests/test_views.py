# Using unicode_literals instead of adding 'u' prefix to all stings that go to SA.
from __future__ import unicode_literals

import flask
import flask_webtest
from keg.db import db
import mock
import pytest
import sqlalchemy as sa

from keg_auth.testing import AuthTests, AuthTestApp, ViewTestBase, login_client_with_permissions

from keg_auth_ta.model import entities as ents


class TestAuthIntegration(AuthTests):
    user_ent = ents.User


class TestViews(object):
    """
        Basic functionality is tested through AuthTests.  The tests in this class cover
        functionality that is specific to the default implementation but might fail depending on
        what customization is made.
    """

    @classmethod
    def setup_class(cls):
        ents.Permission.delete_cascaded()
        cls.perm1 = ents.Permission.testing_create(token='permission1')
        cls.perm2 = ents.Permission.testing_create(token='permission2')

    def setup(self):
        ents.User.delete_cascaded()

    def test_home(self):
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/')
        assert 'Keg Auth Demo' in resp
        assert '/login' in resp
        assert '/logout' not in resp

        user = ents.User.testing_create()
        with client.session_transaction() as sess:
            sess['user_id'] = user.id

        resp = client.get('/')
        assert '/login' not in resp
        assert '/logout' in resp

    def test_auth_base_view(self):
        ents.User.testing_create(email='foo@bar.com', password='pass',
                                 permissions=[self.perm1, self.perm2])

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/secret2', status=302)

        resp = resp.follow()
        resp.form['email'] = 'foo@bar.com'
        resp.form['password'] = 'pass'
        resp = resp.form.submit(status=302)
        assert resp.flashes == [('success', 'Login successful.')]

        # Now that we have logged in, we should be able to get to the page.
        resp = client.get('/secret2', status=200)
        assert resp.text == 'secret2'

    def test_authenticated_client(self):
        user = ents.User.testing_create()
        client = AuthTestApp(flask.current_app, user=user)
        resp = client.get('/secret1', status=200)
        assert resp.text == 'secret1'

        resp = client.get('/secret1-class', status=200)
        assert resp.text == 'secret1-class'

    def test_unauthenticated_client(self):
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/secret1', status=302)
        assert '/login' in resp.location
        resp = client.get('/secret1-class', status=302)
        assert '/login' in resp.location

    def test_authenticated_request(self):
        user = ents.User.testing_create(permissions=[self.perm1, self.perm2])
        client = AuthTestApp(flask.current_app)

        resp = client.get('/secret2', status=200, user=user)
        assert resp.text == 'secret2'

        # User should only stick around for a single request
        client.get('/secret2', status=302)

        # test all HTTP methods
        assert client.post('/secret2', status=200, user=user).text == 'secret2 post'
        assert client.put('/secret2', status=200, user=user).text == 'secret2 put'
        assert client.patch('/secret2', status=200, user=user).text == 'secret2 patch'
        assert client.delete('/secret2', status=200, user=user).text == 'secret2 delete'
        assert client.options('/secret2', status=200, user=user).text == 'secret2 options'
        assert client.head('/secret2', status=200, user=user)
        assert client.post_json('/secret2', status=200, user=user).text == 'secret2 post'
        assert client.put_json('/secret2', status=200, user=user).text == 'secret2 put'
        assert client.patch_json('/secret2', status=200, user=user).text == 'secret2 patch'
        assert client.delete_json('/secret2', status=200, user=user).text == 'secret2 delete'

    def test_login_template(self):
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/login')
        doc = resp.pyquery
        assert doc('title').text() == 'Log In | Keg Auth Demo'
        assert doc('h1').text() == 'Log In'
        assert doc('button').text() == 'Log In'
        assert doc('a').text() == 'I forgot my password'
        assert doc('a').attr('href') == '/forgot-password'

    def test_forgot_pw_template(self):
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/forgot-password')
        doc = resp.pyquery
        assert doc('title').text() == 'Initiate Password Reset | Keg Auth Demo'
        assert doc('h1').text() == 'Initiate Password Reset'
        assert doc('button').text() == 'Send Reset Email'
        assert doc('a').text() == 'Cancel'
        assert doc('a').attr('href') == '/login'

    @mock.patch('keg_auth.views.flask.current_app.auth_mail_manager.send_reset_password',
                autospec=True, spec_set=True)
    def test_forget_pw_actions(self, m_send_reset_password):
        user = ents.User.testing_create(email='foo@bar.com')

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/forgot-password')
        resp.form['email'] = 'foo@bar.com'
        resp = resp.form.submit(status=302)

        # email should be sent
        m_send_reset_password.assert_called_once_with(user)

        # Make sure db updates got committed
        db.session.expire(user)
        assert user.token is not None
        assert user.token_created_utc is not None

    def test_reset_pw_template(self):
        user = ents.User.testing_create()
        user.token_generate()
        url = flask.current_app.auth_manager.reset_password_url(user)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url)
        doc = resp.pyquery
        assert doc('title').text() == 'Complete Password Reset | Keg Auth Demo'
        assert doc('h1').text() == 'Complete Password Reset'
        assert doc('button').text() == 'Change Password'
        assert doc('a').text() == 'Cancel'
        assert doc('a').attr('href') == '/login'

    def test_reset_pw_actions(self):
        user = ents.User.testing_create()
        token = user.token_generate()

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/reset-password/{}/{}'.format(user.id, token))
        resp.form['password'] = resp.form['confirm'] = 'foobar'
        resp = resp.form.submit(status=302)

        # Make sure db updates got committed
        db.session.expire(user)
        assert user.token is None
        assert user.password == 'foobar'

    def test_verify_account_template(self):
        user = ents.User.testing_create()
        user.token_generate()
        url = flask.current_app.auth_manager.verify_account_url(user)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url)
        doc = resp.pyquery
        assert doc('title').text() == 'Verify Account & Set Password | Keg Auth Demo'
        assert doc('h1').text() == 'Verify Account & Set Password'
        assert doc('button').text() == 'Verify & Set Password'
        assert doc('a').text() == 'Cancel'
        assert doc('a').attr('href') == '/login'


class TestPermissionsRequired:
    @classmethod
    def setup_class(cls):
        ents.Permission.delete_cascaded()
        cls.perm1 = ents.Permission.testing_create(token='permission1')
        cls.perm2 = ents.Permission.testing_create(token='permission2')
        cls.perm3 = ents.Permission.testing_create(token='permission3')

    def test_method_level(self):
        allowed = ents.User.testing_create(permissions=[self.perm1, self.perm2])
        disallowed = ents.User.testing_create(permissions=[self.perm1])

        client = AuthTestApp(flask.current_app, user=allowed)
        resp = client.get('/secret2', status=200)
        assert resp.text == 'secret2'

        client = AuthTestApp(flask.current_app, user=disallowed)
        client.post('/secret2', {}, status=403)

    def test_class_level(self):
        allowed = ents.User.testing_create(permissions=[self.perm1, self.perm2])
        disallowed = ents.User.testing_create(permissions=[self.perm1])

        client = AuthTestApp(flask.current_app, user=allowed)
        resp = client.get('/secret3', status=200)
        assert resp.text == 'secret3'

        client = AuthTestApp(flask.current_app, user=disallowed)
        client.get('/secret3', {}, status=403)

        client = flask_webtest.TestApp(flask.current_app)
        client.get('/secret3', status=302)

    def test_class_and_method_level_combined(self):
        allowed = ents.User.testing_create(permissions=[self.perm1, self.perm2])
        disallowed1 = ents.User.testing_create(permissions=[self.perm1])
        disallowed2 = ents.User.testing_create(permissions=[self.perm2])

        client = AuthTestApp(flask.current_app, user=allowed)
        resp = client.get('/secret4', status=200)
        assert resp.text == 'secret4'

        client = AuthTestApp(flask.current_app, user=disallowed1)
        client.get('/secret4', {}, status=403)

        client = AuthTestApp(flask.current_app, user=disallowed2)
        client.get('/secret4', {}, status=403)

        client = flask_webtest.TestApp(flask.current_app)
        client.get('/secret4', status=302)

    def test_nested_conditions(self):
        def check(perms, allowed):
            print(perms, allowed)
            target_status = 200 if allowed else 403
            user = ents.User.testing_create(permissions=perms)

            client = AuthTestApp(flask.current_app, user=user)
            resp = client.get('/secret-nested', status=target_status)
            if allowed:
                assert resp.text == 'secret_nested'

        for perms, allowed in (
            ((self.perm1, self.perm2), True),
            ((self.perm3,), True),
            ((self.perm1,), False),
            ((self.perm2,), False),
            ((self.perm1, self.perm2, self.perm3), True),
        ):
            check(perms, allowed)

    def test_nested_callable_conditions(self):
        def check(perms, email, allowed):
            print(perms, email, allowed)
            ents.User.delete_cascaded()
            target_status = 200 if allowed else 403
            user = ents.User.testing_create(permissions=perms, email=email)

            client = AuthTestApp(flask.current_app, user=user)
            resp = client.get('/secret-nested-callable', status=target_status)
            if allowed:
                assert resp.text == 'secret_nested_callable'

        for perms, email, allowed in (
            ((self.perm1,), 'snoopy@peanuts.com', True),
            ((self.perm2,), 'snoopy@peanuts.com', False),
            ((self.perm2,), 'foo@bar.baz', True),
        ):
            check(perms, email, allowed)

    def test_callable_conditions(self):
        def check(email, allowed):
            print(email, allowed)
            ents.User.delete_cascaded()
            target_status = 200 if allowed else 403
            user = ents.User.testing_create(email=email)

            client = AuthTestApp(flask.current_app, user=user)
            resp = client.get('/secret-callable', status=target_status)
            if allowed:
                assert resp.text == 'secret_callable'

        for email, allowed in (
            ('snoopy@peanuts.com', False),
            ('foo@bar.baz', True),
        ):
            check(email, allowed)


class TestUserCrud(ViewTestBase):
    permissions = 'auth-manage'

    def test_add(self):
        perm_approve = ents.Permission.testing_create()
        ents.Permission.testing_create()
        group_approve = ents.Group.testing_create()
        ents.Group.testing_create()
        bundle_approve = ents.Bundle.testing_create()
        ents.Bundle.testing_create()

        resp = self.client.get('/users/add')

        assert resp.form['email'].value == ''
        assert 'is_superuser' not in resp.form.fields

        resp.form['email'] = 'abc@example.com'
        resp.form['permission_ids'] = [perm_approve.id]
        resp.form['group_ids'] = [group_approve.id]
        resp.form['bundle_ids'] = [bundle_approve.id]

        resp = resp.form.submit()
        assert resp.status_code == 302
        assert resp.location.endswith('/users')
        assert resp.flashes == [('success', 'Successfully created User')]

        user = self.user_ent.get_by(email='abc@example.com')
        assert user.is_enabled is True
        assert user.is_superuser is False
        assert user.permissions == [perm_approve]
        assert user.groups == [group_approve]
        assert user.bundles == [bundle_approve]

    def test_edit(self):
        user_edit = ents.User.testing_create()

        resp = self.client.get('/users/{}'.format(user_edit.id))
        assert resp.form['email'].value == user_edit.email
        resp.form['email'] = 'foo@bar.baz'
        resp = resp.form.submit()

        assert resp.status_code == 302
        assert resp.location.endswith('/users')
        assert resp.flashes == [('success', 'Successfully modified User')]
        assert self.user_ent.get_by(email='foo@bar.baz')

    def test_not_found(self):
        self.client.get('/users/999999', status=404)
        self.client.get('/users/999999/delete', status=404)

    @pytest.mark.parametrize('action', [
        'add', 'edit', 'delete', 'view'
    ])
    def test_alternate_permissions(self, action):
        # patch in separate permissions for add/edit/view/delete
        actions = {'add', 'edit', 'delete', 'view'}
        ents.Permission.testing_create(token='permission1')

        user_edit = ents.User.testing_create()
        user_delete = ents.User.testing_create()

        def url(url_action):
            if url_action == 'view':
                return '/users'
            if url_action == 'edit':
                return '/users/{}'.format(user_edit.id)
            if url_action == 'delete':
                return '/users/{}/delete'.format(user_delete.id)
            return '/users/add'

        with mock.patch.dict(
            flask.current_app.view_functions[
                'auth.user:{}'.format(action)
            ].view_class.permissions,
            {action: 'permission1'}
        ):
            client, _ = login_client_with_permissions('auth-manage')
            client.get(url(action), status=403)
            for url_action in actions.difference({action}):
                print(url_action, url(url_action))
                client.get(url(url_action))

            client, _ = login_client_with_permissions('auth-manage', 'permission1')
            client.get(url(action))

    def test_delete(self):
        user_delete_id = ents.User.testing_create().id

        resp = self.client.get('/users/{}/delete'.format(user_delete_id))

        assert resp.status_code == 302
        assert resp.location.endswith('/users')
        assert resp.flashes == [('success', 'Successfully removed User')]

        assert not self.user_ent.query.get(user_delete_id)

    @mock.patch('keg_auth_ta.model.entities.User.delete', autospec=True, spec_set=True)
    def test_delete_failed(self, m_delete):
        m_delete.side_effect = sa.exc.IntegrityError(None, None, None)
        user_delete_id = ents.User.testing_create().id

        resp = self.client.get('/users/{}/delete'.format(user_delete_id))

        assert resp.status_code == 302
        assert resp.location.endswith('/users')
        assert resp.flashes == [('warning',
                                 'Unable to delete User. It may be referenced by other items.')]

        assert self.user_ent.query.get(user_delete_id)

    def test_view(self):
        ents.User.testing_create()
        resp = self.client.get('/users')
        assert 'datagrid' in resp

    def test_view_export(self):
        ents.User.testing_create()
        resp = self.client.get('/users?export_to=xls')
        assert resp.content_type == 'application/vnd.ms-excel'


class TestGroupCrud(ViewTestBase):
    permissions = 'auth-manage'

    def test_add(self):
        perm_approve = ents.Permission.testing_create()
        ents.Permission.testing_create()
        bundle_approve = ents.Bundle.testing_create()
        ents.Bundle.testing_create()

        resp = self.client.get('/groups/add')

        assert resp.form['name'].value == ''

        resp.form['name'] = 'test adding a group'
        resp.form['permission_ids'] = [perm_approve.id]
        resp.form['bundle_ids'] = [bundle_approve.id]

        resp = resp.form.submit()
        assert resp.status_code == 302
        assert resp.location.endswith('/groups')
        assert resp.flashes == [('success', 'Successfully created Group')]

        group = ents.Group.get_by(name='test adding a group')
        assert group.permissions == [perm_approve]
        assert group.bundles == [bundle_approve]

    def test_edit(self):
        group_edit = ents.Group.testing_create()

        resp = self.client.get('/groups/{}'.format(group_edit.id))
        assert resp.form['name'].value == group_edit.name
        resp.form['name'] = 'test editing a group'
        resp = resp.form.submit()

        assert resp.status_code == 302
        assert resp.location.endswith('/groups')
        assert resp.flashes == [('success', 'Successfully modified Group')]
        assert ents.Group.get_by(name='test editing a group')

    def test_not_found(self):
        self.client.get('/groups/999999', status=404)
        self.client.get('/groups/999999/delete', status=404)

    @pytest.mark.parametrize('action', [
        'add', 'edit', 'delete', 'view'
    ])
    def test_alternate_permissions(self, action):
        # patch in separate permissions for add/edit/view/delete
        actions = {'add', 'edit', 'delete', 'view'}
        ents.Permission.testing_create(token='permission1')

        group_edit = ents.Group.testing_create()
        group_delete = ents.Group.testing_create()

        def url(url_action):
            if url_action == 'view':
                return '/groups'
            if url_action == 'edit':
                return '/groups/{}'.format(group_edit.id)
            if url_action == 'delete':
                return '/groups/{}/delete'.format(group_delete.id)
            return '/groups/add'

        with mock.patch.dict(
            flask.current_app.view_functions[
                'auth.group:{}'.format(action)
            ].view_class.permissions,
            {action: 'permission1'}
        ):
            client, _ = login_client_with_permissions('auth-manage')
            client.get(url(action), status=403)
            for url_action in actions.difference({action}):
                print(url_action, url(url_action))
                client.get(url(url_action))

            client, _ = login_client_with_permissions('auth-manage', 'permission1')
            client.get(url(action))

    def test_delete(self):
        group_delete_id = ents.Group.testing_create().id

        resp = self.client.get('/groups/{}/delete'.format(group_delete_id))

        assert resp.status_code == 302
        assert resp.location.endswith('/groups')
        assert resp.flashes == [('success', 'Successfully removed Group')]

        assert not self.user_ent.query.get(group_delete_id)

    @mock.patch('keg_auth_ta.model.entities.Group.delete', autospec=True, spec_set=True)
    def test_delete_failed(self, m_delete):
        m_delete.side_effect = sa.exc.IntegrityError(None, None, None)
        group_delete_id = ents.Group.testing_create().id

        resp = self.client.get('/groups/{}/delete'.format(group_delete_id))

        assert resp.status_code == 302
        assert resp.location.endswith('/groups')
        assert resp.flashes == [('warning',
                                 'Unable to delete Group. It may be referenced by other items.')]

        assert ents.Group.query.get(group_delete_id)

    def test_view(self):
        ents.Group.testing_create()
        resp = self.client.get('/groups')
        assert 'datagrid' in resp

    def test_view_export(self):
        ents.Group.testing_create()
        resp = self.client.get('/groups?export_to=xls')
        assert resp.content_type == 'application/vnd.ms-excel'


class TestBundleCrud(ViewTestBase):
    permissions = 'auth-manage'

    def test_add(self):
        perm_approve = ents.Permission.testing_create()
        ents.Permission.testing_create()

        resp = self.client.get('/bundles/add')

        assert resp.form['name'].value == ''

        resp.form['name'] = 'test adding a bundle'
        resp.form['permission_ids'] = [perm_approve.id]

        resp = resp.form.submit()
        assert resp.status_code == 302
        assert resp.location.endswith('/bundles')
        assert resp.flashes == [('success', 'Successfully created Bundle')]

        bundle = ents.Bundle.get_by(name='test adding a bundle')
        assert bundle.permissions == [perm_approve]

    def test_edit(self):
        bundle_edit = ents.Bundle.testing_create()

        resp = self.client.get('/bundles/{}'.format(bundle_edit.id))
        assert resp.form['name'].value == bundle_edit.name
        resp.form['name'] = 'test editing a bundle'
        resp = resp.form.submit()

        assert resp.status_code == 302
        assert resp.location.endswith('/bundles')
        assert resp.flashes == [('success', 'Successfully modified Bundle')]
        assert ents.Bundle.get_by(name='test editing a bundle')

    def test_not_found(self):
        self.client.get('/bundles/999999', status=404)
        self.client.get('/bundles/999999/delete', status=404)

    @pytest.mark.parametrize('action', [
        'add', 'edit', 'delete', 'view'
    ])
    def test_alternate_permissions(self, action):
        # patch in separate permissions for add/edit/view/delete
        actions = {'add', 'edit', 'delete', 'view'}
        ents.Permission.testing_create(token='permission1')

        bundle_edit = ents.Bundle.testing_create()
        bundle_delete = ents.Bundle.testing_create()

        def url(url_action):
            if url_action == 'view':
                return '/bundles'
            if url_action == 'edit':
                return '/bundles/{}'.format(bundle_edit.id)
            if url_action == 'delete':
                return '/bundles/{}/delete'.format(bundle_delete.id)
            return '/bundles/add'

        with mock.patch.dict(
            flask.current_app.view_functions[
                'auth.bundle:{}'.format(action)
            ].view_class.permissions,
            {action: 'permission1'}
        ):
            client, _ = login_client_with_permissions('auth-manage')
            client.get(url(action), status=403)
            for url_action in actions.difference({action}):
                print(url_action, url(url_action))
                client.get(url(url_action))

            client, _ = login_client_with_permissions('auth-manage', 'permission1')
            client.get(url(action))

    def test_delete(self):
        bundle_delete_id = ents.Bundle.testing_create().id

        resp = self.client.get('/bundles/{}/delete'.format(bundle_delete_id))

        assert resp.status_code == 302
        assert resp.location.endswith('/bundles')
        assert resp.flashes == [('success', 'Successfully removed Bundle')]

        assert not self.user_ent.query.get(bundle_delete_id)

    @mock.patch('keg_auth_ta.model.entities.Bundle.delete', autospec=True, spec_set=True)
    def test_delete_failed(self, m_delete):
        m_delete.side_effect = sa.exc.IntegrityError(None, None, None)
        bundle_delete_id = ents.Bundle.testing_create().id

        resp = self.client.get('/bundles/{}/delete'.format(bundle_delete_id))

        assert resp.status_code == 302
        assert resp.location.endswith('/bundles')
        assert resp.flashes == [('warning',
                                 'Unable to delete Bundle. It may be referenced by other items.')]

        assert ents.Bundle.query.get(bundle_delete_id)

    def test_view(self):
        ents.Bundle.testing_create()
        resp = self.client.get('/bundles')
        assert 'datagrid' in resp

    def test_view_export(self):
        ents.Bundle.testing_create()
        resp = self.client.get('/bundles?export_to=xls')
        assert resp.content_type == 'application/vnd.ms-excel'
