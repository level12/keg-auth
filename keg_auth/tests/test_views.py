# Using unicode_literals instead of adding 'u' prefix to all stings that go to SA.
from __future__ import unicode_literals
import flask
import freezegun
import arrow
import flask_webtest
from keg.db import db
import mock
import pytest
import sqlalchemy as sa
from keg_auth_ta.app import mail_ext
from keg_auth.testing import AuthTests, AuthTestApp, ViewTestBase

from keg_auth_ta.model import entities as ents
from flask_login import user_logged_in
from .utils import listen_to


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
        cls.perm_auth = ents.Permission.testing_create(token='auth-manage')

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
            sess['user_id'] = user.session_key

        resp = client.get('/')
        assert '/login' not in resp
        assert '/logout' in resp

    def test_auth_base_view(self):
        ents.User.testing_create(email='foo@bar.com', password='pass',
                                 permissions=[self.perm1, self.perm2])

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/secret2', status=302)

        resp = resp.follow()
        resp.form['login_id'] = 'foo@bar.com'
        resp.form['password'] = 'pass'
        resp = resp.form.submit(status=302)
        assert resp.flashes == [('success', 'Login successful.')]

        # Now that we have logged in, we should be able to get to the page.
        resp = client.get('/secret2', status=200)
        assert resp.text == 'secret2'

    def test_rendered_navigation(self):
        ents.User.testing_create(email='foo@bar.com', password='pass',
                                 permissions=[self.perm_auth])

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/')
        doc = resp.pyquery
        assert doc.find('div#navigation a[href="/"]')
        assert not doc.find('div#navigation a[href="/users"]')
        assert not doc.find('div#navigation a[href="/secret-nested"]')

        resp = client.get('/login')
        resp.form['login_id'] = 'foo@bar.com'
        resp.form['password'] = 'pass'
        resp = resp.form.submit(status=302)

        resp = client.get('/')
        doc = resp.pyquery
        assert doc.find('div#navigation a[href="/"]')
        assert doc.find('div#navigation a[href="/users"]')
        assert not doc.find('div#navigation a[href="/secret-nested"]')

        client.get('/logout')
        resp = client.get('/')
        doc = resp.pyquery
        assert doc.find('div#navigation a[href="/"]')
        assert not doc.find('div#navigation a[href="/users"]')
        assert not doc.find('div#navigation a[href="/secret-nested"]')

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
        # decorated class has its own authentication failure handler
        client.get('/secret1-class', status=405)

    @mock.patch('flask.current_app.auth_manager.request_loaders', {})
    def test_unauthenticated_client_no_request_loaders(self):
        client = flask_webtest.TestApp(flask.current_app)
        client.get('/secret1', status=302)

    @freezegun.freeze_time("2018-10-01 15:00:00")
    def test_login_user_sets_last_login_and_invalidates_token(self):
        u = ents.User.testing_create(email='foo@bar.com', password='pass', last_login_utc=None)
        token = u.token_generate()
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/login', status=200)

        resp.form['login_id'] = 'foo@bar.com'
        resp.form['password'] = 'pass'
        with listen_to(user_logged_in) as listener:
            resp = resp.form.submit()
        listener.assert_heard_one(flask.current_app, user=u)

        assert resp.status_code == 302, resp.html
        db.session.remove()
        u = ents.User.get_by(email="foo@bar.com")
        assert u.last_login_utc == arrow.utcnow()
        assert not u.token_verify(token)

    def test_login_field_success_next_parameter(self):
        ents.User.testing_create(email='foo@bar.com', password='pass')

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/secret1', status=302).follow()

        resp.form['login_id'] = 'foo@bar.com'
        resp.form['password'] = 'pass'
        resp = resp.form.submit()

        assert resp.status_code == 302, resp.html
        assert resp.headers['Location'] == 'http://keg.example.com/secret1'
        assert resp.flashes == [('success', 'Login successful.')]

    def test_login_field_success_next_session(self):
        ents.User.testing_create(email='foo@bar.com', password='pass')

        with mock.patch.dict(flask.current_app.config, {'USE_SESSION_FOR_NEXT': True}):
            client = flask_webtest.TestApp(flask.current_app)
            resp = client.get('/secret1', status=302).follow()

            resp.form['login_id'] = 'foo@bar.com'
            resp.form['password'] = 'pass'
            resp = resp.form.submit()

        assert resp.status_code == 302, resp.html
        assert resp.headers['Location'] == 'http://keg.example.com/secret1'
        assert resp.flashes == [('success', 'Login successful.')]

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
        assert doc('div#page-content a').text() == 'I forgot my password'
        assert doc('div#page-content a').attr('href') == '/forgot-password'

    @mock.patch.dict('flask.current_app.config', {'KEGAUTH_EMAIL_OPS_ENABLED': False})
    def test_login_template_no_mail(self):
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/login')
        doc = resp.pyquery
        assert doc('title').text() == 'Log In | Keg Auth Demo'
        assert doc('h1').text() == 'Log In'
        assert doc('button').text() == 'Log In'
        assert not doc('div#page-content a')

    def test_forgot_pw_template(self):
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/forgot-password')
        doc = resp.pyquery
        assert doc('title').text() == 'Initiate Password Reset | Keg Auth Demo'
        assert doc('h1').text() == 'Initiate Password Reset'
        assert doc('button').text() == 'Send Reset Email'
        assert doc('div#page-content a').text() == 'Cancel'
        assert doc('div#page-content a').attr('href') == '/login'

    @mock.patch('keg_auth.views.flask.current_app.auth_manager.mail_manager.send_reset_password',
                autospec=True, spec_set=True)
    def test_forget_pw_actions(self, m_send_reset_password):
        user = ents.User.testing_create(email='foo@bar.com')

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/forgot-password')
        resp.form['email'] = 'foo@bar.com'
        resp = resp.form.submit(status=302)

        # email should be sent
        m_send_reset_password.assert_called_once_with(user)

    @mock.patch('flask.current_app.auth_manager.mail_manager', None)
    def test_forget_pw_actions_mail_disabled(self):
        client = flask_webtest.TestApp(flask.current_app)
        client.get('/forgot-password', status=404)

    def test_reset_pw_template(self):
        user = ents.User.testing_create()
        user.token_generate()
        url = flask.current_app.auth_manager.mail_manager.reset_password_url(user)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url)
        doc = resp.pyquery
        assert doc('title').text() == 'Complete Password Reset | Keg Auth Demo'
        assert doc('h1').text() == 'Complete Password Reset'
        assert doc('button').text() == 'Change Password'
        assert doc('div#page-content a').text() == 'Cancel'
        assert doc('div#page-content a').attr('href') == '/login'

    def test_reset_pw_actions(self):
        user = ents.User.testing_create()
        token = user.token_generate()

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/reset-password/{}/{}'.format(user.id, token))
        resp.form['password'] = resp.form['confirm'] = 'foobar'
        resp = resp.form.submit(status=302)

        # Make sure db updates got committed
        db.session.expire(user)
        assert user.password == 'foobar'

    @mock.patch('flask.current_app.auth_manager.mail_manager', None)
    def test_reset_pw_actions_mail_disabled(self):
        user = ents.User.testing_create()
        token = user.token_generate()

        client = flask_webtest.TestApp(flask.current_app)
        client.get('/reset-password/{}/{}'.format(user.id, token), status=404)

    def test_verify_account_template(self):
        user = ents.User.testing_create()
        user.token_generate()
        url = flask.current_app.auth_manager.mail_manager.verify_account_url(user)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url)
        doc = resp.pyquery
        assert doc('title').text() == 'Verify Account & Set Password | Keg Auth Demo'
        assert doc('h1').text() == 'Verify Account & Set Password'
        assert doc('button').text() == 'Verify & Set Password'
        assert doc('div#page-content a').text() == 'Cancel'
        assert doc('div#page-content a').attr('href') == '/login'


class TestPermissionsRequired:
    @classmethod
    def setup_class(cls):
        ents.Permission.delete_cascaded()
        cls.perm1 = ents.Permission.testing_create(token='permission1')
        cls.perm2 = ents.Permission.testing_create(token='permission2')
        cls.perm3 = ents.Permission.testing_create(token='permission3')

    def test_custom_authentication_failure(self):
        allowed = ents.User.testing_create()
        client = AuthTestApp(flask.current_app, user=allowed)
        resp = client.get('/custom-auth-failure', status=200)
        assert resp.text == 'custom-auth-failure'

        client = flask_webtest.TestApp(flask.current_app)
        client.get('/custom-auth-failure', status=400)

    def test_custom_authorization_failure(self):
        allowed = ents.User.testing_create(permissions=[self.perm1])
        disallowed = ents.User.testing_create()
        client = AuthTestApp(flask.current_app, user=allowed)
        resp = client.get('/custom-perm-failure', status=200)
        assert resp.text == 'custom-perm-failure'

        client = AuthTestApp(flask.current_app, user=disallowed)
        client.get('/custom-perm-failure', status=400)

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

    def test_class_level_inheritance(self):
        allowed = ents.User.testing_create(permissions=[self.perm1, self.perm2])
        disallowed = ents.User.testing_create(permissions=[self.perm1])

        client = AuthTestApp(flask.current_app, user=allowed)
        resp = client.get('/secret3-sub', status=200)
        assert resp.text == 'secret3-sub'

        client = AuthTestApp(flask.current_app, user=disallowed)
        client.get('/secret3-sub', {}, status=403)

        client = flask_webtest.TestApp(flask.current_app)
        client.get('/secret3-sub', status=302)

    def test_class_and_method_level_combined(self):
        allowed = ents.User.testing_create(permissions=[self.perm1, self.perm2])
        disallowed1 = ents.User.testing_create(permissions=[self.perm1])
        disallowed2 = ents.User.testing_create(permissions=[self.perm2])

        client = AuthTestApp(flask.current_app, user=allowed)
        resp = client.get('/secret4', status=200)
        assert resp.text == 'secret4'

        client = AuthTestApp(flask.current_app, user=disallowed1)
        client.get('/secret4', {}, status=403)

        # missing the class-level permission requirement triggers the class's custom auth
        # failure handler
        client = AuthTestApp(flask.current_app, user=disallowed2)
        client.get('/secret4', {}, status=405)

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

    def test_blueprint_method_level(self):
        allowed = ents.User.testing_create(permissions=[self.perm1])
        disallowed = ents.User.testing_create()

        client = AuthTestApp(flask.current_app, user=allowed)
        resp = client.get('/protected-method', status=200)
        assert resp.text == 'protected-method'

        client = AuthTestApp(flask.current_app, user=disallowed)
        client.get('/protected-method', status=403)

    def test_blueprint_class_level(self):
        allowed = ents.User.testing_create(permissions=[self.perm1])
        disallowed = ents.User.testing_create()

        client = AuthTestApp(flask.current_app, user=allowed)
        resp = client.get('/protected-class', status=200)
        assert resp.text == 'protected-class'
        resp = client.get('/protected-class2')
        assert resp.text == 'protected-class2'

        client = AuthTestApp(flask.current_app, user=disallowed)
        client.get('/protected-class', {}, status=403)
        client.get('/protected-class2')

        # blueprint has custom authentication failure hander
        client = flask_webtest.TestApp(flask.current_app)
        client.get('/protected-class', status=405)
        client.get('/protected-class2', status=302)


class TestRequestLoaders(object):
    def test_token_auth_no_token(self):
        client = flask_webtest.TestApp(flask.current_app)
        client.get('/jwt-required', status=302)

    def test_token_auth_with_token(self):
        user = ents.User.testing_create()
        jwt_auth = flask.current_app.auth_manager.get_request_loader('jwt')
        token = jwt_auth.create_access_token(user)

        client = flask_webtest.TestApp(flask.current_app)
        client.set_authorization(('Bearer', token))
        resp = client.get('/jwt-required', status=200)
        assert resp.text == 'jwt-required'


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
        assert 'is_superuser' not in resp.form.fields, resp.form.fields.keys()

        resp.form['email'] = 'abc@example.com'
        resp.form['permission_ids'] = [perm_approve.id]
        resp.form['group_ids'] = [group_approve.id]
        resp.form['bundle_ids'] = [bundle_approve.id]
        with mail_ext.record_messages() as outbox:
            resp = resp.form.submit()
        assert resp.status_code == 302
        assert resp.location.endswith('/users')
        assert resp.flashes == [('success', 'Successfully created User')]
        assert len(outbox) == 1
        assert outbox[0].subject == '[KA Demo] User Welcome & Verification'
        user = self.user_ent.get_by(email='abc@example.com')
        assert user.is_enabled is True
        assert user.is_superuser is False
        assert user.permissions == [perm_approve]
        assert user.groups == [group_approve]
        assert user.bundles == [bundle_approve]

    def test_resend_verification(self):
        self.current_user.is_verified = True
        self.current_user.permissions = ents.Permission.query.filter_by(token='auth-manage').all()
        for user in ents.User.query.filter(ents.User.email != self.current_user.email):
            ents.db.session.delete(user)
        user_edit = self.user_ent.testing_create(
            is_verified=False,
            email="foo1@bar.com",
            is_superuser=False,
            permissions=[]
        )
        resp = self.client.get('/users')
        form = resp.forms[1]

        # assert only one verification link because
        # only one unverified user
        assert 'user_id' not in resp.forms[0].fields
        assert len(resp.forms) == 2
        assert 'user_id' in form.fields
        assert form['user_id'].value == str(user_edit.id)
        with mail_ext.record_messages() as outbox:
            resp = form.submit()

        assert len(outbox) == 1
        assert outbox[0].subject == '[KA Demo] User Welcome & Verification'
        assert 'foo1@bar.com' in outbox[0].recipients
        assert resp.status_code == 302
        assert resp.location.endswith('/users')
        assert resp.flashes == [('success', 'Verification email has been sent')]

    def test_verification_column_appears_when_needed(self):
        resp = self.client.get('/users?op(username)=eq&v1(username)=' + self.current_user.email)
        assert resp.pyquery('.datagrid table.records thead th').eq(4).text() == 'Resend Verification' # noqa
        with mock.patch.dict('flask.current_app.config', {'KEGAUTH_EMAIL_OPS_ENABLED': False}):
            resp = self.client.get('/users?op(username)=eq&v1(username)=' + self.current_user.email)
            assert resp.pyquery('.datagrid table.records thead th').eq(4).text() == ''

    def test_add_and_token_is_correct(self):
        perm_approve = ents.Permission.testing_create()
        ents.Permission.testing_create()
        group_approve = ents.Group.testing_create()
        ents.Group.testing_create()
        bundle_approve = ents.Bundle.testing_create()
        ents.Bundle.testing_create()

        resp = self.client.get('/users/add')

        assert resp.form['email'].value == ''
        assert 'is_superuser' not in resp.form.fields, resp.form.fields.keys()

        resp.form['email'] = 'abc2@example.com'
        resp.form['permission_ids'] = [perm_approve.id]
        resp.form['group_ids'] = [group_approve.id]
        resp.form['bundle_ids'] = [bundle_approve.id]
        with mail_ext.record_messages() as outbox:
            resp = resp.form.submit()
        assert resp.status_code == 302
        assert resp.location.endswith('/users')
        assert resp.flashes == [('success', 'Successfully created User')]
        assert len(outbox) == 1
        assert outbox[0].subject == '[KA Demo] User Welcome & Verification'
        assert 'abc2@example.com' in outbox[0].recipients
        user = self.user_ent.get_by(email='abc2@example.com')
        assert user.token_generate() in outbox[0].as_string()
        assert user.is_enabled is True
        assert user.is_superuser is False
        assert user.permissions == [perm_approve]
        assert user.groups == [group_approve]
        assert user.bundles == [bundle_approve]

    @mock.patch.dict('flask.current_app.config', {'KEGAUTH_EMAIL_OPS_ENABLED': False})
    def test_add_no_email(self):
        resp = self.client.get('/users/add')

        resp.form['email'] = 'foobar@baz.com'
        resp = resp.form.submit()

        assert resp.pyquery('#reset_password').siblings('.help-block').text() == \
            'This field is required.'
        resp.form['reset_password'] = 'bleh'
        resp.form['confirm'] = 'bleh'
        with mail_ext.record_messages() as outbox:
            resp = resp.form.submit()

        assert resp.status_code == 302
        assert resp.location.endswith('/users')
        assert resp.flashes == [('success', 'Successfully created User')]
        assert len(outbox) == 0

        # be sure the password is stored. Force-verify the email so we can continue
        user = self.user_ent.get_by(email='foobar@baz.com')
        user.is_verified = True
        db.session.commit()
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/login')
        resp.form['login_id'] = 'foobar@baz.com'
        resp.form['password'] = 'bleh'
        resp = resp.form.submit()
        assert resp.status_code == 302
        assert resp.location.endswith('/')

    @mock.patch.dict('flask.current_app.config', {'KEGAUTH_EMAIL_OPS_ENABLED': False})
    def test_edit_no_email_same_password(self):
        user = self.user_ent.testing_create()
        resp = self.client.get('/users/{}/edit'.format(user.id))

        resp = resp.form.submit()
        assert resp.status_code == 302
        assert resp.location.endswith('/users')
        assert resp.flashes == [('success', 'Successfully modified User')]

        # be sure the password hasn't changed
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/login')
        resp.form['login_id'] = user.email
        resp.form['password'] = user._plaintext_pass
        resp = resp.form.submit()
        assert resp.status_code == 302
        assert resp.location.endswith('/')

    @mock.patch.dict('flask.current_app.config', {'KEGAUTH_EMAIL_OPS_ENABLED': False})
    def test_edit_no_email_reset_password(self):
        user = self.user_ent.testing_create(password='foobar')
        resp = self.client.get('/users/{}/edit'.format(user.id))

        resp.form['reset_password'] = 'bleh'
        resp.form['confirm'] = 'bleh'
        resp = resp.form.submit()
        assert resp.status_code == 302
        assert resp.location.endswith('/users')
        assert resp.flashes == [('success', 'Successfully modified User')]

        # be sure the password hasn't changed
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('/login')
        resp.form['login_id'] = user.email
        resp.form['password'] = 'bleh'
        resp = resp.form.submit()
        assert resp.status_code == 302
        assert resp.location.endswith('/')

    def test_add_with_session_key(self):
        resp = self.client.get('/users/add?session_key=foo')
        assert resp.pyquery('a.cancel').attr('href').endswith('/users?session_key=foo')

        resp.form['email'] = 'abc@example.session.com'

        resp = resp.form.submit()
        assert resp.status_code == 302
        assert resp.location.endswith('/users?session_key=foo')

    def test_edit(self):
        user_edit = ents.User.testing_create()

        resp = self.client.get('/users/{}/edit'.format(user_edit.id))
        assert resp.form['email'].value == user_edit.email
        resp.form['email'] = 'foo@bar.baz'
        resp = resp.form.submit()

        assert resp.status_code == 302
        assert resp.location.endswith('/users')
        assert resp.flashes == [('success', 'Successfully modified User')]
        assert self.user_ent.get_by(email='foo@bar.baz')

    def test_edit_with_session_key(self):
        user_edit = ents.User.testing_create()

        resp = self.client.get('/users/{}/edit?session_key=foo'.format(user_edit.id))
        assert resp.pyquery('a.cancel').attr('href').endswith('/users?session_key=foo')

        resp = resp.form.submit()
        assert resp.status_code == 302
        assert resp.location.endswith('/users?session_key=foo')

    def test_edit_triggers_user_session_key_refresh(self):
        target_user = ents.User.testing_create(permissions='auth-manage')
        target_user_client = AuthTestApp(flask.current_app, user=target_user)
        new_perm = ents.Permission.testing_create()
        original_session_key = target_user.session_key

        # target user has matching session key and rights to page
        target_user_client.get('/users', status=200)

        resp = self.client.get('/users/{}/edit'.format(target_user.id))
        resp.form['permission_ids'] = [new_perm.id]
        resp = resp.form.submit()

        db.session.expire(target_user)
        assert target_user.session_key != original_session_key

        # target user should need to log in now
        assert '/login' in target_user_client.get('/users', status=302).location

    def test_not_found(self):
        self.client.get('/users/999999/edit', status=404)
        self.client.get('/users/999999/delete', status=404)

    @pytest.mark.parametrize('action', [
        'add', 'edit', 'delete', 'list'
    ])
    def test_alternate_permissions(self, action):
        # patch in separate permissions for add/edit/view/delete
        actions = {'add', 'edit', 'delete', 'list'}
        ents.Permission.testing_create(token='permission1')

        user_edit = ents.User.testing_create()
        user_delete = ents.User.testing_create()

        def url(url_action):
            if url_action == 'list':
                return '/users'
            if url_action == 'edit':
                return '/users/{}/edit'.format(user_edit.id)
            if url_action == 'delete':
                return '/users/{}/delete'.format(user_delete.id)
            return '/users/add'

        with mock.patch.dict(
            flask.current_app.view_functions[
                'auth.user:{}'.format(action)
            ].view_class.permissions,
            {action: 'permission1'}
        ):
            user = ents.User.testing_create(permissions='auth-manage')
            client = AuthTestApp(flask.current_app, user=user)
            client.get(url(action), status=403)
            for url_action in actions.difference({action}):
                print(url_action, url(url_action))
                client.get(url(url_action))

            user = ents.User.testing_create(permissions=('auth-manage', 'permission1'))
            client = AuthTestApp(flask.current_app, user=user)
            client.get(url(action))

    def test_delete(self):
        user_delete_id = ents.User.testing_create().id

        resp = self.client.get('/users/{}/delete'.format(user_delete_id))

        assert resp.status_code == 302
        assert resp.location.endswith('/users')
        assert resp.flashes == [('success', 'Successfully removed User')]

        assert not self.user_ent.query.get(user_delete_id)

    def test_delete_with_session_key(self):
        user_delete = ents.User.testing_create()

        resp = self.client.get('/users/{}/delete?session_key=foo'.format(user_delete.id))

        assert resp.status_code == 302
        assert resp.location.endswith('/users?session_key=foo')

    def test_delete_myself_fails(self):
        resp = self.client.get('/users/{}/delete'.format(self.current_user.id))

        assert resp.status_code == 302
        assert resp.location.endswith('/users')
        assert resp.flashes == [('warning',
                                 'Unable to delete User. It may be referenced by other items.')]

    @mock.patch('keg_elements.db.mixins.db.session.delete', autospec=True, spec_set=True)
    def test_delete_failed(self, m_delete):
        m_delete.side_effect = sa.exc.IntegrityError(None, None, None)
        user_delete_id = ents.User.testing_create().id

        resp = self.client.get('/users/{}/delete'.format(user_delete_id))

        assert resp.status_code == 302
        assert resp.location.endswith('/users')
        assert resp.flashes == [('warning',
                                 'Unable to delete User. It may be referenced by other items.')]

        assert self.user_ent.query.get(user_delete_id)

    def test_list(self):
        resp = self.client.get('/users?op(username)=eq&v1(username)=' + self.current_user.email)
        assert resp.pyquery('.grid-header-add-link a').attr('href').startswith('/users/add')
        assert resp.pyquery('.datagrid table.records thead th').eq(1).text() == 'User ID'
        assert resp.pyquery('.datagrid table.records tbody td').eq(1).text() == self.current_user.email  # noqa

    def test_list_alternate_ident_field(self):
        # with the mock here, authentication/authorization will also be happening on the alternate
        # class, which doesn't have relationships like permissions. So, to make this easy, make it
        # a superuser.
        user = ents.UserNoEmail.testing_create(is_superuser=True)
        client = AuthTestApp(flask.current_app, user=user)
        with mock.patch('keg_auth_ta.extensions.auth_entity_registry._user_cls', ents.UserNoEmail):
            resp = client.get('/users?op(username)=eq&v1(username)=' + user.username)
            assert resp.pyquery('.datagrid table.records thead th').eq(1).text() == 'User ID'
            assert resp.pyquery('.datagrid table.records tbody td').eq(1).text() == user.username

    def test_list_export(self):
        ents.User.testing_create()
        resp = self.client.get('/users?export_to=xlsx')
        assert resp.content_type == 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'  # noqa


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

        resp = self.client.get('/groups/{}/edit'.format(group_edit.id))
        assert resp.form['name'].value == group_edit.name
        resp.form['name'] = 'test editing a group'
        resp = resp.form.submit()

        assert resp.status_code == 302
        assert resp.location.endswith('/groups')
        assert resp.flashes == [('success', 'Successfully modified Group')]
        assert ents.Group.get_by(name='test editing a group')

    def test_not_found(self):
        self.client.get('/groups/999999/edit', status=404)
        self.client.get('/groups/999999/delete', status=404)

    @pytest.mark.parametrize('action', [
        'add', 'edit', 'delete', 'list'
    ])
    def test_alternate_permissions(self, action):
        # patch in separate permissions for add/edit/view/delete
        actions = {'add', 'edit', 'delete', 'list'}
        ents.Permission.testing_create(token='permission1')

        group_edit = ents.Group.testing_create()
        group_delete = ents.Group.testing_create()

        def url(url_action):
            if url_action == 'list':
                return '/groups'
            if url_action == 'edit':
                return '/groups/{}/edit'.format(group_edit.id)
            if url_action == 'delete':
                return '/groups/{}/delete'.format(group_delete.id)
            return '/groups/add'

        with mock.patch.dict(
            flask.current_app.view_functions[
                'auth.group:{}'.format(action)
            ].view_class.permissions,
            {action: 'permission1'}
        ):
            user = ents.User.testing_create(permissions='auth-manage')
            client = AuthTestApp(flask.current_app, user=user)
            client.get(url(action), status=403)
            for url_action in actions.difference({action}):
                print(url_action, url(url_action))
                client.get(url(url_action))

            user = ents.User.testing_create(permissions=('auth-manage', 'permission1'))
            client = AuthTestApp(flask.current_app, user=user)
            client.get(url(action))

    def test_delete(self):
        group_delete_id = ents.Group.testing_create().id

        resp = self.client.get('/groups/{}/delete'.format(group_delete_id))

        assert resp.status_code == 302
        assert resp.location.endswith('/groups')
        assert resp.flashes == [('success', 'Successfully removed Group')]

        assert not ents.Group.query.get(group_delete_id)

    @mock.patch('keg_elements.db.mixins.db.session.delete', autospec=True, spec_set=True)
    def test_delete_failed(self, m_delete):
        m_delete.side_effect = sa.exc.IntegrityError(None, None, None)
        group_delete_id = ents.Group.testing_create().id

        resp = self.client.get('/groups/{}/delete'.format(group_delete_id))

        assert resp.status_code == 302
        assert resp.location.endswith('/groups')
        assert resp.flashes == [('warning',
                                 'Unable to delete Group. It may be referenced by other items.')]

        assert ents.Group.query.get(group_delete_id)

    def test_list(self):
        ents.Group.testing_create()
        resp = self.client.get('/groups')
        assert resp.pyquery('.grid-header-add-link a').attr('href').startswith('/groups/add')
        assert 'datagrid' in resp

    def test_list_export(self):
        ents.Group.testing_create()
        resp = self.client.get('/groups?export_to=xlsx')
        assert resp.content_type == 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'  # noqa


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

        resp = self.client.get('/bundles/{}/edit'.format(bundle_edit.id))
        assert resp.form['name'].value == bundle_edit.name
        resp.form['name'] = 'test editing a bundle'
        resp = resp.form.submit()

        assert resp.status_code == 302
        assert resp.location.endswith('/bundles')
        assert resp.flashes == [('success', 'Successfully modified Bundle')]
        assert ents.Bundle.get_by(name='test editing a bundle')

    def test_not_found(self):
        self.client.get('/bundles/999999/edit', status=404)
        self.client.get('/bundles/999999/delete', status=404)

    @pytest.mark.parametrize('action', [
        'add', 'edit', 'delete', 'list'
    ])
    def test_alternate_permissions(self, action):
        # patch in separate permissions for add/edit/view/delete
        actions = {'add', 'edit', 'delete', 'list'}
        ents.Permission.testing_create(token='permission1')

        bundle_edit = ents.Bundle.testing_create()
        bundle_delete = ents.Bundle.testing_create()

        def url(url_action):
            if url_action == 'list':
                return '/bundles'
            if url_action == 'edit':
                return '/bundles/{}/edit'.format(bundle_edit.id)
            if url_action == 'delete':
                return '/bundles/{}/delete'.format(bundle_delete.id)
            return '/bundles/add'

        with mock.patch.dict(
            flask.current_app.view_functions[
                'auth.bundle:{}'.format(action)
            ].view_class.permissions,
            {action: 'permission1'}
        ):
            user = ents.User.testing_create(permissions='auth-manage')
            client = AuthTestApp(flask.current_app, user=user)
            client.get(url(action), status=403)
            for url_action in actions.difference({action}):
                print(url_action, url(url_action))
                client.get(url(url_action))

            user = ents.User.testing_create(permissions=('auth-manage', 'permission1'))
            client = AuthTestApp(flask.current_app, user=user)
            client.get(url(action))

    def test_delete(self):
        bundle_delete_id = ents.Bundle.testing_create().id

        resp = self.client.get('/bundles/{}/delete'.format(bundle_delete_id))

        assert resp.status_code == 302
        assert resp.location.endswith('/bundles')
        assert resp.flashes == [('success', 'Successfully removed Bundle')]

        assert not ents.Bundle.query.get(bundle_delete_id)

    @mock.patch('keg_elements.db.mixins.db.session.delete', autospec=True, spec_set=True)
    def test_delete_failed(self, m_delete):
        m_delete.side_effect = sa.exc.IntegrityError(None, None, None)
        bundle_delete_id = ents.Bundle.testing_create().id

        resp = self.client.get('/bundles/{}/delete'.format(bundle_delete_id))

        assert resp.status_code == 302
        assert resp.location.endswith('/bundles')
        assert resp.flashes == [('warning',
                                 'Unable to delete Bundle. It may be referenced by other items.')]

        assert ents.Bundle.query.get(bundle_delete_id)

    def test_list(self):
        ents.Bundle.testing_create()
        resp = self.client.get('/bundles')
        assert resp.pyquery('.grid-header-add-link a').attr('href').startswith('/bundles/add')
        assert 'datagrid' in resp

    def test_list_export(self):
        ents.Bundle.testing_create()
        resp = self.client.get('/bundles?export_to=xlsx')
        assert resp.content_type == 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'  # noqa


class TestPermissionsView(ViewTestBase):
    permissions = 'auth-manage'

    def test_list(self):
        ents.Permission.testing_create()
        resp = self.client.get('/permissions')
        assert not resp.pyquery('.grid-header-add-link')
        assert 'datagrid' in resp

    def test_list_export(self):
        ents.Permission.testing_create()
        resp = self.client.get('/permissions?export_to=xlsx')
        assert resp.content_type == 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'  # noqa
