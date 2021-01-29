# Using unicode_literals instead of adding 'u' prefix to all stings that go to SA.
from __future__ import unicode_literals

from datetime import timedelta
from unittest import mock
from urllib.parse import quote, urlparse

import arrow
import flask
import flask_webtest
import passlib
import pytest
import wrapt
from blazeutils import randchars, tolist
from blazeutils.containers import LazyDict
from keg import current_app

from keg_auth.libs.authenticators import AttemptLimitMixin

try:
    has_attempt_model = flask.current_app.auth_manager.entity_registry.is_registered('attempt')
except RuntimeError as exc:
    if 'application context' not in str(exc):
        raise
    has_attempt_model = False

has_attempt_skip_reason = 'no attempt model registered in entity registry'


class AuthAttemptTests(object):
    """Tests to verify that automated attempt logging/blocking works as intended. These
    tests are included in the AuthTests class and are intended to be used in target
    applications to verify customization hasn't broken basic KegAuth functionality."""
    forgot_invalid_flashes = [('error', 'No user account matches: foo@bar.com')]
    forgot_lockout_flashes = [('error', 'Too many failed attempts.')]
    forgot_success_flashes = [
        ('success', 'Please check your email for the link to change your password.')
    ]

    login_invalid_flashes = [('error', 'Invalid password.')]
    login_lockout_flashes = [('error', 'Too many failed login attempts.')]
    login_success_flashes = [('success', 'Login successful.')]

    reset_lockout_flashes = [('error', 'Too many password reset attempts.')]
    reset_success_flashes = [
        ('success', 'Password changed.  Please use the new password to login below.')
    ]

    def setup(self):
        if has_attempt_model:
            self.attempt_ent.delete_cascaded()

    @classmethod
    def setup_class(cls):
        if has_attempt_model:
            cls.attempt_ent = flask.current_app.auth_manager.entity_registry.attempt_cls
        cls.client = flask_webtest.TestApp(flask.current_app)

    def do_login(self, client, email, password, submit_status=200):
        login_url = flask.url_for(flask.current_app.auth_manager.endpoint('login'))
        resp = client.get(login_url)
        resp.form['login_id'] = email
        resp.form['password'] = password
        return resp.form.submit(status=submit_status)

    def do_login_test(self, username, login_time, flashes, password='badpass',
                      submit_status=200, client=None):
        with mock.patch(
            'keg_auth.libs.authenticators.arrow.utcnow',
            return_value=login_time,
        ):
            resp = self.do_login(client or self.client, username, password, submit_status)
            assert resp.flashes == flashes

    @pytest.mark.skipif(not has_attempt_model, reason=has_attempt_skip_reason)
    @pytest.mark.parametrize('limit, timespan, lockout', [
        (3, 3600, 7200),
        (3, 7200, 300),
        (5, 300, 300),
    ])
    @pytest.mark.parametrize('create_user', [
        False,
        True,
    ])
    def test_login_attempts_blocked(self, limit, timespan, lockout, create_user):
        '''
        Test that login attempts get blocked after reaching the failed login attempt
        limit. Login attempts after the lockout period has passed (since the failed attempt
        that caused the lockout) should not be blocked.
        '''
        with mock.patch.dict('flask.current_app.config', {
            'KEGAUTH_LOGIN_ATTEMPT_LIMIT': limit,
            'KEGAUTH_LOGIN_ATTEMPT_TIMESPAN': timespan,
            'KEGAUTH_LOGIN_ATTEMPT_LOCKOUT': lockout,
        }):
            # We want to test blocking attempts for existing and non-existing users.
            username = 'foo@bar.com'
            invalid_flashes = [('error', 'No user account matches: foo@bar.com')]
            success_flashes = [('error', 'No user account matches: foo@bar.com')]
            if create_user:
                invalid_flashes = self.login_invalid_flashes
                success_flashes = self.login_success_flashes
                self.user_ent.testing_create(email=username, password='pass')

            assert self.attempt_ent.query.count() == 0

            last_attempt_time = arrow.utcnow()
            first_attempt_time = last_attempt_time + timedelta(seconds=-(timespan - 1))
            before_lockout_end = last_attempt_time + timedelta(seconds=lockout)
            after_lockout_end = last_attempt_time + timedelta(seconds=lockout + 1)

            def assert_attempt_count(attempt_count, failed_count, is_during_lockout=False):
                assert self.attempt_ent.query.filter_by(
                    user_input=username,
                    attempt_type='login',
                    is_during_lockout=is_during_lockout,
                ).count() == attempt_count
                assert self.attempt_ent.query.filter_by(
                    user_input=username,
                    attempt_type='login',
                    success=False,
                    is_during_lockout=is_during_lockout,
                ).count() == failed_count

            def do_test(login_time, flashes, password='badpass', submit_status=200):
                self.do_login_test(username, login_time, flashes, password, submit_status)

            do_test(first_attempt_time, invalid_flashes)
            assert_attempt_count(1, 1)
            assert_attempt_count(0, 0, is_during_lockout=True)
            for i in range(0, limit - 2):
                attempt_time = first_attempt_time + timedelta(seconds=i+1)
                do_test(attempt_time, invalid_flashes)
                assert_attempt_count(i + 2, i + 2)
                assert_attempt_count(0, 0, is_during_lockout=True)

            do_test(last_attempt_time, invalid_flashes)
            assert_attempt_count(limit, limit)
            assert_attempt_count(0, 0, is_during_lockout=True)

            # Test attempts blocked at start of lockout.
            do_test(last_attempt_time + timedelta(seconds=1), self.login_lockout_flashes, 'pass')
            assert_attempt_count(limit, limit)
            assert_attempt_count(1, 1, is_during_lockout=True)

            # Test attempts blocked just before end of lockout.
            for i in range(0, limit):
                attempt_time = before_lockout_end - timedelta(seconds=i + 1)
                do_test(attempt_time, self.login_lockout_flashes)
                assert_attempt_count(limit, limit)
                assert_attempt_count(2 + i, i + 2, is_during_lockout=True)

            # Test attempts not blocked after lockout. Note that even though in the
            # previous loop we attempted (limit) times unsuccessfully, those attempts
            # do not count against the limit counter because they were done during
            # lockout.
            status = 302 if create_user else 200
            fail_count = limit + (0 if create_user else 1)
            do_test(after_lockout_end, success_flashes, 'pass', status)
            assert_attempt_count(limit + 1, fail_count)
            assert_attempt_count(limit + 1, limit + 1, is_during_lockout=True)

    @pytest.mark.skipif(not has_attempt_model, reason=has_attempt_skip_reason)
    @mock.patch.dict('flask.current_app.config', {
        'KEGAUTH_LOGIN_ATTEMPT_LIMIT': 3,
        'KEGAUTH_LOGIN_ATTEMPT_TIMESPAN': 3600,
        'KEGAUTH_LOGIN_ATTEMPT_LOCKOUT': 7200,
    })
    @mock.patch('flask.current_app.auth_manager.entity_registry._attempt_cls',
                new_callable=mock.PropertyMock(return_value=None))
    def test_login_attempts_not_blocked(self, _):
        '''
        Test that we do not block any attempts with missing attempt entity.
        '''
        user = self.user_ent.testing_create(email='foo@bar.com', password='pass')
        assert self.attempt_ent.query.count() == 0

        def do_test(attempt_count, flashes, password='badpass', submit_status=200):
            resp = self.do_login(self.client, user.email, password, submit_status)
            assert self.attempt_ent.query.filter_by(
                user_input=user.email, attempt_type='login').count() == attempt_count
            assert resp.flashes == flashes

        do_test(0, self.login_invalid_flashes)
        do_test(0, self.login_invalid_flashes)
        do_test(0, self.login_invalid_flashes)
        do_test(0, self.login_invalid_flashes)
        do_test(0, self.login_success_flashes, 'pass', 302)

    @pytest.mark.skipif(not has_attempt_model, reason=has_attempt_skip_reason)
    @pytest.mark.parametrize('limit, timespan, lockout', [
        (3, 3600, 7200),
        (3, 7200, 300),
        (5, 300, 300),
    ])
    def test_successful_login_resets_attempt_counter(self, limit, timespan, lockout):
        '''
        Test that several failed logins before a successful login do not count
        towards the attempt lockout counter.
        '''
        with mock.patch.dict('flask.current_app.config', {
            'KEGAUTH_LOGIN_ATTEMPT_LIMIT': limit,
            'KEGAUTH_LOGIN_ATTEMPT_TIMESPAN': timespan,
            'KEGAUTH_LOGIN_ATTEMPT_LOCKOUT': lockout,
        }):
            user = self.user_ent.testing_create(email='foo@bar.com', password='pass')
            assert self.attempt_ent.query.count() == 0

            # Login and assert matching flashes and status.
            def do_test(login_time, flashes, password='badpass', submit_status=200):
                self.do_login_test(user.email, login_time, flashes, password, submit_status)

            login_time = arrow.utcnow()
            # Create (limit - 1) failed login attempts. The next failed login
            # would cause a lockout.
            for i in range(0, limit - 1):
                attempt_time = login_time + timedelta(seconds=-(i + 1))
                do_test(attempt_time, self.login_invalid_flashes)

            # Create a successful login to reset the attempt counter.
            do_test(login_time, self.login_success_flashes, 'pass', 302)

            # We can attempt (limit) more times after a successful login before
            # getting locked out.
            for i in range(0, limit):
                failed_login_time = login_time + timedelta(seconds=i + 1)
                do_test(failed_login_time, self.login_invalid_flashes)

            # We should be locked out now because we did (limit) failed attempts
            # after the successful attempt.
            do_test(login_time + timedelta(seconds=limit + 1), self.login_lockout_flashes)

    @pytest.mark.skipif(not has_attempt_model, reason=has_attempt_skip_reason)
    @pytest.mark.parametrize('limit, timespan, lockout', [
        (3, 3600, 7200),
    ])
    def test_login_attempts_blocked_by_ip(self, limit, timespan, lockout):
        '''
        Test that login attempts get blocked for an IP address
        '''
        client = flask_webtest.TestApp(flask.current_app,
                                       extra_environ={'REMOTE_ADDR': '192.168.0.111'})

        with mock.patch.dict('flask.current_app.config', {
            'KEGAUTH_LOGIN_ATTEMPT_LIMIT': limit,
            'KEGAUTH_LOGIN_ATTEMPT_TIMESPAN': timespan,
            'KEGAUTH_LOGIN_ATTEMPT_LOCKOUT': lockout,
            'KEGAUTH_ATTEMPT_IP_LIMIT': True,
        }):
            def invalid_flashes(email):
                return [('error', f'No user account matches: {email}')]

            last_attempt_time = arrow.utcnow()
            first_attempt_time = last_attempt_time + timedelta(seconds=-(timespan - 1))

            def assert_attempt_count(attempt_count, failed_count, is_during_lockout=False):
                assert self.attempt_ent.query.filter_by(
                    attempt_type='login',
                    is_during_lockout=is_during_lockout,
                ).count() == attempt_count
                assert self.attempt_ent.query.filter_by(
                    attempt_type='login',
                    success=False,
                    is_during_lockout=is_during_lockout,
                ).count() == failed_count

            def do_test(username, login_time, flashes, submit_status=200, client=client):
                self.do_login_test(username, login_time, flashes, 'pass',
                                   submit_status, client=client)

            for i in range(0, limit):
                email = randchars() + '@foo.com'
                attempt_time = first_attempt_time + timedelta(seconds=i+1)
                do_test(email, attempt_time, invalid_flashes(email))

            assert_attempt_count(limit, limit)
            assert_attempt_count(0, 0, is_during_lockout=True)

            # Test attempts blocked at start of lockout.
            email = randchars() + '@foo.com'
            do_test(email, last_attempt_time + timedelta(seconds=1), self.login_lockout_flashes)
            assert_attempt_count(limit, limit)
            assert_attempt_count(1, 1, is_during_lockout=True)

            # Attempt from another IP is not locked
            do_test(email, last_attempt_time + timedelta(seconds=1), invalid_flashes(email),
                    client=self.client)

    def do_forgot(self, client, email, submit_status=200):
        forgot_url = flask.url_for(flask.current_app.auth_manager.endpoint('forgot-password'))
        resp = client.get(forgot_url)
        resp.form['email'] = email
        return resp.form.submit(status=submit_status)

    def do_forgot_test(self, username, forgot_time, flashes, submit_status=200):
        with mock.patch(
            'keg_auth.libs.authenticators.arrow.utcnow',
            return_value=forgot_time,
        ):
            resp = self.do_forgot(self.client, username, submit_status)
            assert resp.flashes == flashes

    @pytest.mark.skipif(not has_attempt_model, reason=has_attempt_skip_reason)
    @pytest.mark.parametrize('limit, timespan, lockout', [
        (3, 3600, 7200),
        (3, 7200, 300),
        (5, 300, 300),
    ])
    def test_forgot_attempts_blocked(self, limit, timespan, lockout):
        '''
        Test that forgot attempts get blocked after reaching the failed forgot attempt
        limit. forgot attempts after the lockout period has passed (since the failed attempt
        that caused the lockout) should not be blocked.
        '''
        with mock.patch.dict('flask.current_app.config', {
            'KEGAUTH_FORGOT_ATTEMPT_LIMIT': limit,
            'KEGAUTH_FORGOT_ATTEMPT_TIMESPAN': timespan,
            'KEGAUTH_FORGOT_ATTEMPT_LOCKOUT': lockout,
        }):
            # We want to test blocking attempts for existing and non-existing users.
            username = 'foo@bar.com'
            invalid_flashes = [('error', 'No user account matches: foo@bar.com')]
            success_flashes = [('error', 'No user account matches: foo@bar.com')]

            assert self.attempt_ent.query.count() == 0

            last_attempt_time = arrow.utcnow()
            first_attempt_time = last_attempt_time + timedelta(seconds=-(timespan - 1))
            before_lockout_end = last_attempt_time + timedelta(seconds=lockout)
            after_lockout_end = last_attempt_time + timedelta(seconds=lockout + 1)

            def assert_attempt_count(attempt_count, failed_count, is_during_lockout=False):
                assert self.attempt_ent.query.filter_by(
                    user_input=username,
                    attempt_type='forgot',
                    is_during_lockout=is_during_lockout,
                ).count() == attempt_count
                assert self.attempt_ent.query.filter_by(
                    user_input=username,
                    attempt_type='forgot',
                    success=False,
                    is_during_lockout=is_during_lockout,
                ).count() == failed_count

            def do_test(forgot_time, flashes, submit_status=200):
                self.do_forgot_test(username, forgot_time, flashes, submit_status)

            do_test(first_attempt_time, invalid_flashes)
            assert_attempt_count(1, 1)
            assert_attempt_count(0, 0, is_during_lockout=True)
            for i in range(0, limit - 2):
                attempt_time = first_attempt_time + timedelta(seconds=i+1)
                do_test(attempt_time, invalid_flashes)
                assert_attempt_count(i + 2, i + 2)
                assert_attempt_count(0, 0, is_during_lockout=True)

            do_test(last_attempt_time, invalid_flashes)
            assert_attempt_count(limit, limit)
            assert_attempt_count(0, 0, is_during_lockout=True)

            # Test attempts blocked at start of lockout.
            do_test(last_attempt_time + timedelta(seconds=1), self.forgot_lockout_flashes)
            assert_attempt_count(limit, limit)
            assert_attempt_count(1, 1, is_during_lockout=True)

            # Test attempts blocked just before end of lockout.
            for i in range(0, limit):
                attempt_time = before_lockout_end - timedelta(seconds=i + 1)
                do_test(attempt_time, self.forgot_lockout_flashes)
                assert_attempt_count(limit, limit)
                assert_attempt_count(2 + i, i + 2, is_during_lockout=True)

            # Test attempts not blocked after lockout. Note that even though in the
            # previous loop we attempted (limit) times unsuccessfully, those attempts
            # do not count against the limit counter because they were done during
            # lockout.
            status = 200
            fail_count = limit + 1
            do_test(after_lockout_end, success_flashes, status)
            assert_attempt_count(limit + 1, fail_count)
            assert_attempt_count(limit + 1, limit + 1, is_during_lockout=True)

    @pytest.mark.skipif(not has_attempt_model, reason=has_attempt_skip_reason)
    @mock.patch.dict('flask.current_app.config', {
        'KEGAUTH_FORGOT_ATTEMPT_LIMIT': 3,
        'KEGAUTH_FORGOT_ATTEMPT_TIMESPAN': 3600,
        'KEGAUTH_FORGOT_ATTEMPT_LOCKOUT': 7200,
    })
    @mock.patch('flask.current_app.auth_manager.entity_registry._attempt_cls',
                new_callable=mock.PropertyMock(return_value=None))
    def test_forgot_attempts_not_blocked(self, _):
        '''
        Test that we do not block any attempts with missing attempt entity.
        '''
        assert self.attempt_ent.query.count() == 0

        def do_test(attempt_count, flashes, submit_status=200):
            resp = self.do_forgot(self.client, 'foo@bar.com', submit_status)
            assert self.attempt_ent.query.filter_by(
                user_input='foo@bar.com', attempt_type='forgot').count() == attempt_count
            assert resp.flashes == flashes

        do_test(0, self.forgot_invalid_flashes)
        do_test(0, self.forgot_invalid_flashes)

    @pytest.mark.skipif(not has_attempt_model, reason=has_attempt_skip_reason)
    @pytest.mark.parametrize('limit, timespan, lockout', [
        (3, 3600, 7200),
        (3, 7200, 300),
        (5, 300, 300),
    ])
    def test_successful_forgot_resets_attempt_counter(self, limit, timespan, lockout):
        '''
        Test that several failed forgots before a successful forgot do not count
        towards the attempt lockout counter.
        '''
        with mock.patch.dict('flask.current_app.config', {
            'KEGAUTH_FORGOT_ATTEMPT_LIMIT': limit,
            'KEGAUTH_FORGOT_ATTEMPT_TIMESPAN': timespan,
            'KEGAUTH_FORGOT_ATTEMPT_LOCKOUT': lockout,
        }):
            assert self.attempt_ent.query.count() == 0

            # forgot and assert matching flashes and status.
            def do_test(forgot_time, flashes, submit_status=200):
                self.do_forgot_test('foo@bar.com', forgot_time, flashes, submit_status)

            forgot_time = arrow.utcnow()
            # Create (limit - 1) failed forgot attempts. The next failed forgot
            # would cause a lockout.
            for i in range(0, limit - 1):
                attempt_time = forgot_time + timedelta(seconds=-(i + 1))
                do_test(attempt_time, self.forgot_invalid_flashes)

            # Create a successful forgot to reset the attempt counter.
            user = self.user_ent.testing_create(email='foo@bar.com')
            self.do_forgot_test(user.email, forgot_time, self.forgot_success_flashes,
                                submit_status=302)
            self.user_ent.delete(user.id)

            # We can attempt (limit) more times after a successful forgot before
            # getting locked out.
            for i in range(0, limit):
                failed_forgot_time = forgot_time + timedelta(seconds=i + 1)
                do_test(failed_forgot_time, self.forgot_invalid_flashes)

            # We should be locked out now because we did (limit) failed attempts
            # after the successful attempt.
            do_test(forgot_time + timedelta(seconds=limit + 1), self.forgot_lockout_flashes)

    def do_reset_test(self, user, reset_time, flashes, submit_status=200):
        with mock.patch(
            'keg_auth.libs.authenticators.arrow.utcnow',
            return_value=reset_time,
        ):
            token = user.token_generate()
            url = flask.url_for(flask.current_app.auth_manager.endpoint('reset-password'),
                                user_id=user.id, token=token)
            resp = self.client.get(url, status=200)
            new_pass = randchars(8)
            resp.form['password'] = new_pass
            resp.form['confirm'] = new_pass
            resp = resp.form.submit(status=submit_status)
            assert resp.flashes == flashes

    @pytest.mark.skipif(not has_attempt_model, reason=has_attempt_skip_reason)
    @pytest.mark.parametrize('limit, timespan, lockout', [
        (3, 3600, 7200),
        (3, 7200, 300),
        (5, 300, 300),
    ])
    def test_reset_pw_attempts_blocked(self, limit, timespan, lockout):
        '''
        Test that login attempts get blocked after reaching the failed login attempt
        limit. Login attempts after the lockout period has passed (since the failed attempt
        that caused the lockout) should not be blocked.
        '''
        with mock.patch.dict('flask.current_app.config', {
            'KEGAUTH_RESET_ATTEMPT_LIMIT': limit,
            'KEGAUTH_RESET_ATTEMPT_TIMESPAN': timespan,
            'KEGAUTH_RESET_ATTEMPT_LOCKOUT': lockout,
        }):
            user = self.user_ent.testing_create(email='foo@bar.com', password='pass')
            assert self.attempt_ent.query.count() == 0

            last_attempt_time = arrow.utcnow()
            first_attempt_time = last_attempt_time + timedelta(seconds=-(timespan - 1))
            before_lockout_end = last_attempt_time + timedelta(seconds=lockout)
            after_lockout_end = last_attempt_time + timedelta(seconds=lockout + 1)

            def assert_attempt_count(attempt_count, failed_count, is_during_lockout=False):
                assert self.attempt_ent.query.filter_by(
                    user_input=user.email,
                    attempt_type='reset',
                    is_during_lockout=is_during_lockout,
                ).count() == attempt_count
                assert self.attempt_ent.query.filter_by(
                    user_input=user.email,
                    attempt_type='reset',
                    success=False,
                    is_during_lockout=is_during_lockout,
                ).count() == failed_count

            def do_test(reset_time, flashes, submit_status=200):
                self.do_reset_test(user, reset_time, flashes, submit_status)

            do_test(first_attempt_time, self.reset_success_flashes, 302)
            assert_attempt_count(1, 0)
            assert_attempt_count(0, 0, is_during_lockout=True)
            for i in range(0, limit - 2):
                attempt_time = first_attempt_time + timedelta(seconds=i + 1)
                do_test(attempt_time, self.reset_success_flashes, 302)
                assert_attempt_count(i + 2, 0)
                assert_attempt_count(0, 0, is_during_lockout=True)

            do_test(last_attempt_time, self.reset_success_flashes, 302)
            assert_attempt_count(limit, 0)
            assert_attempt_count(0, 0, is_during_lockout=True)

            # Test attempts blocked at start of lockout.
            do_test(last_attempt_time + timedelta(seconds=1), self.reset_lockout_flashes)
            assert_attempt_count(limit, 0)
            assert_attempt_count(1, 1, is_during_lockout=True)

            # Test attempts blocked just before end of lockout.
            for i in range(0, limit):
                attempt_time = before_lockout_end - timedelta(seconds=i + 1)
                do_test(attempt_time, self.reset_lockout_flashes)
                assert_attempt_count(limit, 0)
                assert_attempt_count(2 + i, 2 + i, is_during_lockout=True)

            # Test attempts not blocked after lockout. Note that even though in the
            # previous loop we attempted (limit) times unsuccessfully, those attempts
            # do not count against the limit counter because they were done during
            # lockout.
            do_test(after_lockout_end, self.reset_success_flashes, 302)
            assert_attempt_count(limit + 1, 0)
            assert_attempt_count(limit + 1, limit + 1, is_during_lockout=True)

    @pytest.mark.skipif(not has_attempt_model, reason=has_attempt_skip_reason)
    @mock.patch.dict('flask.current_app.config', {
        'KEGAUTH_RESET_ATTEMPT_LIMIT': 2,
        'KEGAUTH_RESET_ATTEMPT_TIMESPAN': 3600,
        'KEGAUTH_RESET_ATTEMPT_LOCKOUT': 7200,
    })
    @mock.patch('flask.current_app.auth_manager.entity_registry._attempt_cls',
                new_callable=mock.PropertyMock(return_value=None))
    def test_reset_pw_attempts_not_blocked(self, _):
        user = self.user_ent.testing_create()
        assert self.attempt_ent.query.count() == 0

        def do_test(reset_time, flashes, submit_status=200):
            self.do_reset_test(user, reset_time, flashes, submit_status)

        do_test(arrow.utcnow(), self.reset_success_flashes, 302)
        do_test(arrow.utcnow(), self.reset_success_flashes, 302)
        do_test(arrow.utcnow(), self.reset_success_flashes, 302)
        do_test(arrow.utcnow(), self.reset_success_flashes, 302)

    @pytest.mark.skipif(not has_attempt_model, reason=has_attempt_skip_reason)
    @mock.patch('keg_auth.libs.authenticators.AttemptLimitMixin.get_request_remote_addr',
                return_value='12.12.12.12')
    def test_logs_attempt_source_ip(self, m_get_remote_addr):
        user = self.user_ent.testing_create(email='foo@bar.com', password='pass')
        self.do_login(self.client, user.email, 'pass', 302)

        assert self.attempt_ent.query.one().source_ip == m_get_remote_addr.return_value

    @pytest.mark.skipif(not has_attempt_model, reason=has_attempt_skip_reason)
    def test_get_request_remote_addr(self):
        with current_app.test_request_context(environ_base={'REMOTE_ADDR': '12.12.12.12'}):
            assert AttemptLimitMixin.get_request_remote_addr() == '12.12.12.12'


class AuthTests(AuthAttemptTests):
    """
        These tests are designed so they can can be imported into an application's tests
        and ran to ensure customization of KegAuth hasn't broken basic functionality.
    """
    protected_url = '/secret1'
    protected_url_permissions = None

    def setup(self):
        super().setup()
        self.user_ent.delete_cascaded()

    def test_login_get(self):
        app = flask.current_app
        client = flask_webtest.TestApp(app)
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('login')))
        assert resp.status_code == 200

    def test_login_head(self):
        client = flask_webtest.TestApp(flask.current_app)
        client.head(
            flask.url_for(flask.current_app.auth_manager.endpoint('login')),
            status=405,
        )

    def test_login_form_error(self):
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('login')))

        resp.form['login_id'] = 'foo'
        resp = resp.form.submit(status=200)

        flash_form_error = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['login'].flash_form_error
        category = flash_form_error[1]
        message = flash_form_error[0]
        assert resp.flashes == [(category, message)]

    def test_login_field_success(self):
        user = self.user_ent.testing_create(email='foo@bar.com', password='pass')

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('login')))

        resp.form['login_id'] = 'foo@bar.com'
        resp.form['password'] = 'pass'
        resp = resp.form.submit()

        assert resp.status_code == 302, resp.html
        assert resp.headers['Location'] == flask.url_for(
            flask.current_app.auth_manager.endpoint('after-login')
        )
        flash_success = flask.current_app.auth_manager.login_authenticator_cls.responder_cls['login'].flash_success  # noqa
        category = flash_success[1]
        message = flash_success[0]
        assert resp.flashes == [(category, message)]
        if has_attempt_model:
            assert self.attempt_ent.query.count() == 1
            assert self.attempt_ent.query.filter_by(
                attempt_type='login',
                success=True,
                user_input=user.email,
                is_during_lockout=False,
            )

    def test_login_field_success_next_parameter(self):
        self.user_ent.testing_create(email='foo@bar.com', password='pass')

        next = '/foo'
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('{}?next={}'.format(
            flask.url_for(flask.current_app.auth_manager.endpoint('login')), next)
        )

        resp.form['login_id'] = 'foo@bar.com'
        resp.form['password'] = 'pass'
        resp = resp.form.submit()

        assert resp.status_code == 302, resp.html
        assert resp.headers['Location'] == 'http://keg.example.com{}'.format(next)
        flash_success = flask.current_app.auth_manager.login_authenticator_cls.responder_cls['login'].flash_success  # noqa
        category = flash_success[1]
        message = flash_success[0]
        assert resp.flashes == [(category, message)]

    def test_login_field_success_next_session(self):
        self.user_ent.testing_create(email='foo@bar.com', password='pass')

        next = '/foo'
        with mock.patch.dict(flask.current_app.config, {'USE_SESSION_FOR_NEXT': True}):
            client = flask_webtest.TestApp(flask.current_app)
            with client.session_transaction() as sess:
                sess['next'] = next
            resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('login')))

            resp.form['login_id'] = 'foo@bar.com'
            resp.form['password'] = 'pass'
            resp = resp.form.submit()

        assert resp.status_code == 302, resp.html
        assert resp.headers['Location'] == 'http://keg.example.com{}'.format(next)
        flash_success = flask.current_app.auth_manager.login_authenticator_cls.responder_cls['login'].flash_success  # noqa
        category = flash_success[1]
        message = flash_success[0]
        assert resp.flashes == [(category, message)]

    def test_next_parameter_not_open_redirect(self):
        """ensure following the "next" parameter doesn't allow for an open redirect"""
        self.user_ent.testing_create(email='foo@bar.com', password='pass')

        # unquoted next parameter
        next = 'http://www.example.com'
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get('{}?next={}'.format(
            flask.url_for(flask.current_app.auth_manager.endpoint('login')), next
            )
        )

        resp.form['login_id'] = 'foo@bar.com'
        resp.form['password'] = 'pass'
        resp = resp.form.submit()

        assert resp.status_code == 302, resp.html
        # verify the 'next' parameter was ignored
        assert resp.headers['Location'] == flask.url_for(
            flask.current_app.auth_manager.endpoint('after-login')
        )
        flash_success = flask.current_app.auth_manager.login_authenticator_cls.responder_cls['login'].flash_success  # noqa
        category = flash_success[1]
        message = flash_success[0]
        assert resp.flashes == [(category, message)]

        # quoted next parameter
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(
            '{}?next={}'.format(
                flask.url_for(flask.current_app.auth_manager.endpoint('login')),
                quote(next)
            )
        )

        resp.form['login_id'] = 'foo@bar.com'
        resp.form['password'] = 'pass'
        resp = resp.form.submit()

        assert resp.status_code == 302, resp.html
        # verify the 'next' parameter was ignored
        assert resp.headers['Location'] == flask.url_for(
            flask.current_app.auth_manager.endpoint('after-login')
        )
        flash_success = flask.current_app.auth_manager.login_authenticator_cls.responder_cls['login'].flash_success  # noqa
        category = flash_success[1]
        message = flash_success[0]
        assert resp.flashes == [(category, message)]

    def test_login_invalid_password(self):
        user = self.user_ent.testing_create(email='foo@bar.com', password='pass')
        if has_attempt_model:
            assert self.attempt_ent.query.count() == 0

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('login')))

        resp.form['login_id'] = 'foo@bar.com'
        resp.form['password'] = 'badpass'
        resp = resp.form.submit(status=200)

        flash_invalid_password = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['login'].flash_invalid_password
        category = flash_invalid_password[1]
        message = flash_invalid_password[0]
        assert resp.flashes == [(category, message)]
        if has_attempt_model:
            assert self.attempt_ent.query.count() == 1
            assert self.attempt_ent.get_by(
                attempt_type='login',
                success=False,
                user_input=user.email,
                is_during_lockout=False,
            )

    def test_login_user_missing(self):
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('login')))

        resp.form['login_id'] = 'foo@bar.com'
        resp.form['password'] = 'badpass'
        resp = resp.form.submit(status=200)

        flash_invalid_user = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['login'].flash_invalid_user
        category = flash_invalid_user[1]
        message = flash_invalid_user[0]
        assert resp.flashes == [(category, message.format('foo@bar.com'))]

    def test_login_user_unverified(self):
        self.user_ent.testing_create(email='foo@bar.com', password='pass', is_verified=False)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('login')))

        resp.form['login_id'] = 'foo@bar.com'
        resp.form['password'] = 'badpass'
        resp = resp.form.submit(status=200)

        flash_unverified_user = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['login'].flash_unverified_user
        category = flash_unverified_user[1]
        message = flash_unverified_user[0]
        assert resp.flashes == [(category, message.format('foo@bar.com'))]

    def test_login_user_disabled(self):
        self.user_ent.testing_create(email='foo@bar.com', password='pass', is_enabled=False)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('login')))

        resp.form['login_id'] = 'foo@bar.com'
        resp.form['password'] = 'badpass'
        resp = resp.form.submit(status=200)

        flash_disabled_user = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['login'].flash_disabled_user
        category = flash_disabled_user[1]
        message = flash_disabled_user[0]
        assert resp.flashes == [(category, message.format('foo@bar.com'))]

    def test_login_protection(self):
        self.user_ent.testing_create(
            email='foo@bar.com', password='pass', permissions=self.protected_url_permissions
        )

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(self.protected_url, status=302)
        full_login_url = 'http://keg.example.com{}'.format(
            urlparse(flask.url_for(flask.current_app.auth_manager.endpoint('login'))).path
        )
        assert resp.headers['Location'].startswith(full_login_url)

        resp = resp.follow()
        resp.form['login_id'] = 'foo@bar.com'
        resp.form['password'] = 'pass'
        resp = resp.form.submit(status=302)
        flash_success = flask.current_app.auth_manager.login_authenticator_cls.responder_cls['login'].flash_success  # noqa
        category = flash_success[1]
        message = flash_success[0]
        assert resp.flashes == [(category, message)]

        # Now that we have logged in, we should be able to get to the page.
        client.get(self.protected_url, status=200)

    def test_forgot_pw_form_error(self):
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('forgot-password')))
        resp = resp.form.submit(status=200)

        flash_form_error = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['forgot-password'].flash_form_error
        category = flash_form_error[1]
        message = flash_form_error[0]
        assert resp.flashes == [(category, message)]

    def test_forgot_pw_invalid_user(self):
        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('forgot-password')))

        resp.form['email'] = 'foo@bar.com'
        resp = resp.form.submit(status=200)

        flash_invalid_user = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['forgot-password'].flash_invalid_user
        category = flash_invalid_user[1]
        message = flash_invalid_user[0]
        assert resp.flashes == [(category, message.format('foo@bar.com'))]

    def test_forgot_pw_user_disabled(self):
        self.user_ent.testing_create(email='foo@bar.com', password='pass', is_enabled=False)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('forgot-password')))

        resp.form['email'] = 'foo@bar.com'
        resp = resp.form.submit(status=200)

        flash_disabled_user = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['forgot-password'].flash_disabled_user
        category = flash_disabled_user[1]
        message = flash_disabled_user[0]
        assert resp.flashes == [(category, message.format('foo@bar.com'))]

    def test_forgot_pw_success(self):
        self.user_ent.testing_create(email='foo@bar.com')

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('forgot-password')))

        resp.form['email'] = 'foo@bar.com'
        resp = resp.form.submit(status=302)

        flash_success = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['forgot-password'].flash_success
        category = flash_success[1]
        message = flash_success[0]
        assert resp.flashes == [(category, message)]

        full_login_url = 'http://keg.example.com{}'.format(
            urlparse(flask.url_for(flask.current_app.auth_manager.endpoint('login'))).path
        )
        assert resp.headers['Location'] == full_login_url

    def test_reset_pw_success(self):
        user = self.user_ent.testing_create()
        if has_attempt_model:
            assert self.attempt_ent.query.count() == 0
        token = user.token_generate()
        url = flask.url_for(flask.current_app.auth_manager.endpoint('reset-password'),
                            user_id=user.id, token=token)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url, status=200)

        resp.form['password'] = 'fooBar123'
        resp.form['confirm'] = 'fooBar123'
        resp = resp.form.submit(status=302)

        flash_success = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['reset-password'].flash_success
        category = flash_success[1]
        message = flash_success[0]
        assert resp.flashes == [(category, message)]

        full_login_url = 'http://keg.example.com{}'.format(
            urlparse(flask.url_for(flask.current_app.auth_manager.endpoint('login'))).path
        )
        assert resp.headers['Location'] == full_login_url
        if has_attempt_model:
            assert self.attempt_ent.query.count() == 1
            assert self.attempt_ent.get_by(attempt_type='reset', user_input=user.email)

    def test_reset_pw_form_error(self):
        user = self.user_ent.testing_create()
        token = user.token_generate()
        url = flask.url_for(flask.current_app.auth_manager.endpoint('reset-password'),
                            user_id=user.id, token=token)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url, status=200)
        resp = resp.form.submit(status=200)

        flash_form_error = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['reset-password'].flash_form_error
        category = flash_form_error[1]
        message = flash_form_error[0]
        assert resp.flashes == [(category, message)]

    def test_reset_pw_missing_user(self):
        url = flask.url_for(flask.current_app.auth_manager.endpoint('reset-password'),
                            user_id='99999999', token='123')

        client = flask_webtest.TestApp(flask.current_app)
        client.get(url, status=404)

    def test_reset_pw_bad_token(self):
        user = self.user_ent.testing_create()
        url = flask.url_for(flask.current_app.auth_manager.endpoint('reset-password'),
                            user_id=user.id, token='abc')

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url, status=302)

        flash_invalid_token = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['reset-password'].flash_invalid_token
        category = flash_invalid_token[1]
        message = flash_invalid_token[0]
        assert resp.flashes == [(category, message)]

        full_forgot_password_url = 'http://keg.example.com{}'.format(
            urlparse(flask.url_for(flask.current_app.auth_manager.endpoint('forgot-password'))).path
        )
        assert resp.headers['Location'] == full_forgot_password_url

    def test_verify_account_success(self):
        user = self.user_ent.testing_create(is_verified=False)
        assert not user.is_verified

        user.token_generate()
        url = flask.current_app.auth_manager.mail_manager.verify_account_url(user)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url, status=200)

        resp.form['password'] = 'fooBar123'
        resp.form['confirm'] = 'fooBar123'
        resp = resp.form.submit(status=302)

        flash_success = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['verify-account'].flash_success
        category = flash_success[1]
        message = flash_success[0]
        assert resp.flashes == [(category, message)]

        full_login_url = 'http://keg.example.com{}'.format(
            urlparse(flask.url_for(flask.current_app.auth_manager.endpoint('login'))).path
        )
        assert resp.headers['Location'] == full_login_url

        assert user.is_verified

    def test_verify_account_form_error(self):
        user = self.user_ent.testing_create()
        user.token_generate()
        url = flask.current_app.auth_manager.mail_manager.verify_account_url(user)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url, status=200)
        resp = resp.form.submit(status=200)

        flash_form_error = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['verify-account'].flash_form_error
        category = flash_form_error[1]
        message = flash_form_error[0]
        assert resp.flashes == [(category, message)]

    def test_verify_account_missing_user(self):
        user = LazyDict(id=9999999, _token_plain='123')
        url = flask.current_app.auth_manager.mail_manager.verify_account_url(user)

        client = flask_webtest.TestApp(flask.current_app)
        client.get(url, status=404)

    def test_verify_account_bad_token(self):
        user = self.user_ent.testing_create()
        user._token_plain = 'abc'
        url = flask.current_app.auth_manager.mail_manager.verify_account_url(user)

        client = flask_webtest.TestApp(flask.current_app)
        resp = client.get(url, status=302)

        flash_invalid_token = flask.current_app.auth_manager.login_authenticator_cls.\
            responder_cls['verify-account'].flash_invalid_token
        category = flash_invalid_token[1]
        message = flash_invalid_token[0]
        assert resp.flashes == [(category, message)]

        full_forgot_password_url = 'http://keg.example.com{}'.format(
            urlparse(flask.url_for(flask.current_app.auth_manager.endpoint('forgot-password'))).path
        )
        assert resp.headers['Location'] == full_forgot_password_url

    def test_logout(self):
        user = self.user_ent.testing_create(permissions=self.protected_url_permissions)
        client = flask_webtest.TestApp(flask.current_app)
        with client.session_transaction() as sess:
            sess['_user_id'] = user.session_key

        # Make sure our client is actually logged in
        client.get(self.protected_url, status=200)

        # logout
        resp = client.get(flask.url_for(flask.current_app.auth_manager.endpoint('logout')),
                          status=302)
        assert resp.flashes == [('success', 'You have been logged out.')]

        # Check redirect location
        full_after_logout_url = flask.url_for(flask.current_app.auth_manager.
                                              endpoint('after-logout'))
        assert resp.headers['Location'] == full_after_logout_url

        # Confirm logout occured
        client.get(self.protected_url, status=302)


@wrapt.decorator
def user_request(wrapped, instance, args, kwargs):
    new_kwargs = kwargs.copy()
    user = new_kwargs.pop('user', None)
    extra_environ = new_kwargs.setdefault('extra_environ', {})
    if user is not None:
        extra_environ['TEST_USER_ID'] = str(user.session_key)
    return wrapped(*args, **new_kwargs)


def with_crypto_context(field, context=None):
    """Wrap a test to use a real cryptographic context for a :class:`KAPasswordType`

    Temporarily assign a :class:`passlib.context.CryptoContext` to a particular entity column.

    :param context (optional): :class:`passlib.context.CryptoContext` to use for this test. The
        default value is `keg_auth.core.DEFAULT_CRYPTO_SCHEMES`.

    .. NOTE:

    In most situations we don't want a real crypto scheme to run in the tests, it is
    slow on entities like Users which have a password. ``User.testing_create`` will generate a value
    for that instance and then hash which takes a bunch of time. However, when testing certain
    schemes, it is useful to execute the real behavior instead of the ``plaintext`` behaviour.

    ::

        import bcrypt

        bcrypt_context = passlib.context.CryptContext(scheme=['bcrypt'])

        @with_crypto_context(ents.User.password, context=bcrypt_context)
        def test_with_real_context():
            user = ents.User.testing_create(password='abc')
            assert bcrypt.checkpw('abc', user.password.hash)

    """
    import keg_auth

    @wrapt.decorator
    def wrapper(wrapped, instance, args, kwargs):
        prev_context = field.type.context
        field.type.context = (
            context or passlib.context.CryptContext(schemes=keg_auth.core.DEFAULT_CRYPTO_SCHEMES)
        )

        wrapped(*args, **kwargs)

        field.type.context = prev_context

    return wrapper


class AuthTestApp(flask_webtest.TestApp):
    """Wrapper of `flask_webtest.TestApp` that will inject a user into the session.

    Pass in a user instance to "log in" the session:

        user = User.testing_create(permissions=['auth-manage', 'do-something'])
        test_app = AuthTestApp(flask.current_app, user=user)

    When running integration tests, following the view sequence to log a user in can
    be quite time-consuming and unnecessary. Login tests can be elsewhere. Once a user
    is logged in, they are identified by their `session_key`. So, we simply inject
    that key in the environment, and then follow the request out to webtest per
    normal.
    """
    def __init__(self, app, **kwargs):
        user = kwargs.pop('user', None)
        extra_environ = kwargs.pop('extra_environ', {})
        if user is not None:
            extra_environ['TEST_USER_ID'] = str(user.session_key)
        super(AuthTestApp, self).__init__(app, extra_environ=extra_environ, **kwargs)

    @user_request
    def get(self, *args, **kwargs):
        return super(AuthTestApp, self).get(*args, **kwargs)

    @user_request
    def post(self, *args, **kwargs):
        return super(AuthTestApp, self).post(*args, **kwargs)

    @user_request
    def put(self, *args, **kwargs):
        return super(AuthTestApp, self).put(*args, **kwargs)

    @user_request
    def patch(self, *args, **kwargs):
        return super(AuthTestApp, self).patch(*args, **kwargs)

    @user_request
    def delete(self, *args, **kwargs):
        return super(AuthTestApp, self).delete(*args, **kwargs)

    @user_request
    def options(self, *args, **kwargs):
        return super(AuthTestApp, self).options(*args, **kwargs)

    @user_request
    def head(self, *args, **kwargs):
        return super(AuthTestApp, self).head(*args, **kwargs)

    @user_request
    def post_json(self, *args, **kwargs):
        return super(AuthTestApp, self).post_json(*args, **kwargs)

    @user_request
    def put_json(self, *args, **kwargs):
        return super(AuthTestApp, self).put_json(*args, **kwargs)

    @user_request
    def patch_json(self, *args, **kwargs):
        return super(AuthTestApp, self).patch_json(*args, **kwargs)

    @user_request
    def delete_json(self, *args, **kwargs):
        return super(AuthTestApp, self).delete_json(*args, **kwargs)


class ViewTestBase:
    """ Simple helper class that will set up Permission tokens as specified, log in a user, and
        provide the test app client on the class for use in tests.

        Usage: `permissions` class attribute can be scalar or list.

        For tests:
        - `self.current_user`: User instance that is logged in
        - `self.client`: AuthTestApp instance
    """
    permissions = tuple()

    @classmethod
    def setup_class(cls):
        cls.user_ent = flask.current_app.auth_manager.entity_registry.user_cls
        cls.permission_ent = flask.current_app.auth_manager.entity_registry.permission_cls
        cls.user_ent.delete_cascaded()

        # ensure all of the tokens exists
        defined_perms = set(
            tolist(perm)[0] for perm in flask.current_app.auth_manager.permissions
        )
        for perm in tolist(cls.permissions):
            if perm not in defined_perms:
                raise Exception('permission {} not specified in the auth manager'.format(perm))
            cls.permission_ent.testing_create(token=perm)

        cls.current_user = cls.user_ent.testing_create(permissions=cls.permissions)
        cls.client = AuthTestApp(flask.current_app, user=cls.current_user)
