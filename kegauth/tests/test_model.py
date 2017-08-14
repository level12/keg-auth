# Using unicode_literals instead of adding 'u' prefix to all stings that go to SA.
from __future__ import unicode_literals

import arrow
import flask
from freezegun import freeze_time
from kegauth_ta.model import entities as ents
import mock


class TestUser(object):
    def setup(self):
        ents.User.delete_cascaded()

    def test_email_case_insensitive(self):
        ents.User.testing_create(email='foo@BAR.com')

        assert ents.User.get_by(email='foo@bar.com')

    def test_is_verified_default(self):
        # testing_create() overrides the is_enabled default to make testing easier.  So, make sure
        # that we have set enabled to False when not used in a testing environment.
        user = ents.User.add(email='foo', password='bar')
        assert not user.is_verified
        assert user.password == 'bar'

    def test_is_active_python_attribute(self):
        # By default, user is inactive because email has not been verified.
        user = ents.User.testing_create(is_verified=False)
        assert user.is_enabled
        assert not user.is_verified
        assert not user.is_active

        # Once email has been verified, user should be active.
        user = ents.User.testing_create()
        assert user.is_active

        # Verified but disabled is also inactive.
        user = ents.User.testing_create(is_verified=True, is_enabled=False)
        assert not user.is_active

    def test_is_active_sql_expression(self):
        ents.User.testing_create(email='1', is_verified=False, is_enabled=True)
        ents.User.testing_create(email='2', is_verified=True, is_enabled=True)
        ents.User.testing_create(email='3', is_verified=True, is_enabled=False)

        assert ents.User.query.filter_by(email='1', is_active=False).one()
        assert ents.User.query.filter_by(email='2', is_active=True).one()
        assert ents.User.query.filter_by(email='3', is_active=False).one()

    def test_token_validation_null_fields(self):
        # Make sure verification doesn't fail when both token related fields are NULL.
        user = ents.User.add(email='f', password='p')
        assert not user.token_verify('foo')

    def test_token_validation(self):
        user = ents.User.testing_create(token_created_utc=None)

        assert user.token is None
        assert not user.token_verify(None)

        token = user.token_generate()
        assert token
        assert user.token is not None
        assert not user.token_verify('foo')
        assert user.token_verify(token)
        assert user.token_verify(token)

    def test_token_expiration(self):
        user = ents.User.add(email='foo', password='bar')
        assert user.token_created_utc is None
        token = user.token_generate()
        now = arrow.get()
        assert user.token_created_utc <= now

        with mock.patch.dict(flask.current_app.config, KEGAUTH_TOKEN_EXPIRE_MINS=10):
            plus_9_58 = now.shift(minutes=9, seconds=58).datetime
            with freeze_time(plus_9_58):
                assert user.token_verify(token)
            plus_10 = now.shift(minutes=10).datetime
            with freeze_time(plus_10):
                assert not user.token_verify(token)

    def test_change_password(self):
        user = ents.User.testing_create(is_verified=False)
        token = user.token_generate()
        user.change_password(token, 'abc123')
        assert not user.token_verify(token)
        assert user.password == 'abc123'
        assert user.is_verified
