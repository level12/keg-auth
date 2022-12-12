import base64
import hashlib
import string
import time
from authlib import jose
import arrow
import flask
from keg.db import db
import pytest
from freezegun import freeze_time
import sqlalchemy as sa
import bcrypt

from keg_auth.model import InvalidToken, entity_registry, utils
from keg_auth_ta.model import entities as ents
from keg_auth.testing import with_crypto_context
import mock


class TestUserTokenMixin(object):
    def setup_method(self):
        ents.UserWithToken.delete_cascaded()

    @with_crypto_context(ents.UserWithToken.token)
    def test_token_storage_with_real_bcrypt(self):
        raw_token = b'a' * 32
        uwt = ents.UserWithToken.fake(token=raw_token)
        assert bcrypt.checkpw(raw_token, uwt.token.hash)

    @with_crypto_context(ents.UserWithToken.token)
    def test_reset_auth_token(self):
        original_token = b'a' * 32
        uwt = ents.UserWithToken.fake(token=original_token)

        assert bcrypt.checkpw(original_token, uwt.token.hash)
        new_token = uwt.reset_auth_token()

        assert bcrypt.checkpw(new_token.encode(), uwt.token.hash)
        assert not bcrypt.checkpw(original_token, uwt.token.hash)

    def test_generate_auth_token(self):
        assert len(ents.UserWithToken.generate_raw_auth_token(length=1)) == 1
        assert len(ents.UserWithToken.generate_raw_auth_token()) == 32
        assert len(ents.UserWithToken.generate_raw_auth_token(entropy='secure')) == 32
        assert len(ents.UserWithToken.generate_raw_auth_token(length=None, entropy='secure')) == 11
        assert (string.ascii_uppercase not in
                ents.UserWithToken.generate_raw_auth_token(charset='hex'))

    @pytest.mark.parametrize('raw,test,result', [
        ('123', '123', True),
        ('123', 'abc', False),
        ('a' * 400, 'abc', False),
        (b'abc', b'abc', True),
        (b'abc', 'abc', True),
        ('abc', b'abc', True),
        (None, b'abc', False),
        ('abc', None, False),
    ])
    def test_verify_token(self, raw, test, result):
        uwt = ents.UserWithToken.fake(token=raw)
        assert uwt.verify_token(test) is result

    def test_generate_api_token(self):
        u1 = ents.UserWithToken.fake()
        raw_token = u1.generate_api_token()

        raw_email, token = raw_token.split('.')
        real_email = base64.urlsafe_b64decode(raw_email.encode()).decode()

        assert (real_email, token) == (u1.email, u1.token.hash.decode())

    def test_get_user_for_api_token_happy_path(self):
        u1 = ents.UserWithToken.fake(email='test@test.com', token='1234')
        ents.UserWithToken.fake(email='test-2@test.com', token='5678')

        u1_api_token = u1.generate_api_token('1234')
        assert ents.UserWithToken.get_user_for_api_token(u1_api_token).id == u1.id

    def test_get_user_for_api_token_wrong_token(self):
        u1 = ents.UserWithToken.fake(email='test@test.com', token='1234')
        ents.UserWithToken.fake(email='test-2@test.com', token='5678')

        u1_api_token = u1.generate_api_token('1234')
        u1_raw_email, u1_raw_token = u1_api_token.split('.')
        u1_fake_token = '{email}.faketoken'.format(email=u1_raw_email)

        assert ents.UserWithToken.get_user_for_api_token(u1_fake_token) is None

    @pytest.mark.parametrize('token', [
        None,  # Bad
        'test@testcom',  # No period
        'tes.t@te.stcom',  # three periods
        b'test@thing.token',  # not b64encoded
    ])
    def test_get_user_for_api_token_bad_token(self, token):
        assert ents.UserWithToken.get_user_for_api_token(token) is None


class TestUser(object):
    def setup_method(self):
        ents.User.delete_cascaded()
        ents.Permission.delete_cascaded()

    def test_email_case_insensitive(self):
        ents.User.fake(email='foo@BAR.com')

        assert ents.User.get_by(email='foo@bar.com')

    def test_is_verified_default(self):
        # fake() overrides the is_enabled default to make testing easier.  So, make sure
        # that we have set enabled to False when not used in a testing environment.
        user = ents.User.add(email='foo', password='bar')
        assert not user.is_verified
        assert user.password == 'bar'

    @pytest.mark.parametrize('is_enabled, is_verified, disabled_utc, is_active', [
        (True, True, None, True),
        (True, True, arrow.utcnow().shift(minutes=+5), True),
        (True, False, None, False),
        (False, True, None, False),
        (True, True, arrow.utcnow().shift(minutes=-5), False),
    ])
    def test_is_active_python_attribute(self, is_enabled, is_verified, disabled_utc, is_active):
        user = ents.User.fake(
            is_verified=is_verified,
            is_enabled=is_enabled,
            disabled_utc=disabled_utc,
        )
        assert user.is_active == is_active

    @pytest.mark.parametrize('is_enabled, is_verified, disabled_utc, is_active', [
        (True, True, None, True),
        (True, True, arrow.utcnow().shift(minutes=+5), True),
        (True, False, None, False),
        (False, True, None, False),
        (True, True, arrow.utcnow().shift(minutes=-5), False),
    ])
    def test_is_active_sql_expression(self, is_enabled, is_verified, disabled_utc, is_active):
        ents.User.fake(
            email='email',
            is_verified=is_verified,
            is_enabled=is_enabled,
            disabled_utc=disabled_utc,
        )
        assert ents.User.query.filter_by(email='email', is_active=is_active).one()

    def test_token_validation(self):
        user = ents.User.fake()

        assert not hasattr(user, '_token_plain')
        assert not user.token_verify(None)

        token = user.token_generate()
        assert token
        assert not user.token_verify('foo')
        assert user.token_verify(token)
        assert user.token_verify(user._token_plain)

    def test_legacy_token(self):
        """
        Mimic an itsdangerous token and validate it only verifies in legacy mode.
        - sha1 signature instead of sha512
        - iat/exp claims are in header, not payload
        """
        user = ents.User.fake()
        base_key = user.get_token_salt() + 'signer' + flask.current_app.config.get('SECRET_KEY')
        signature = hashlib.sha1(base_key.encode()).digest()
        now = int(time.time())
        exp = now + (flask.current_app.config.get('KEGAUTH_TOKEN_EXPIRE_MINS') * 60)
        header = {'alg': 'HS512', 'iat': now, 'exp': exp}
        payload = {'user_id': user.id}
        token = jose.jwt.encode(header, payload, signature)

        assert user.token_verify(token)
        assert not user.token_verify(token, _block_legacy=True)

    def test_token_salt_info_changed(self):
        def check_field(field, new_value):
            user = ents.User.fake(last_login_utc=None)
            token = user.token_generate()
            setattr(user, field, new_value)
            db.session.flush()
            db.session.commit()
            db.session.refresh(user)
            assert not user.token_verify(token)

        check_field('email', 'foobar')
        check_field('is_enabled', False)
        check_field('is_verified', False)
        check_field('password', 'foobar')
        check_field('last_login_utc', arrow.utcnow())

    def test_token_expiration(self):
        user = ents.User.add(email='foo', password='bar')

        with mock.patch.dict(flask.current_app.config, KEGAUTH_TOKEN_EXPIRE_MINS=10):
            token = user.token_generate()
            now = arrow.get()
            assert user.token_verify(token)

            plus_9_58 = now.shift(minutes=9, seconds=58).datetime
            with freeze_time(plus_9_58):
                assert user.token_verify(token)
            plus_10_01 = now.shift(minutes=10, seconds=1).datetime
            with freeze_time(plus_10_01):
                assert not user.token_verify(token)

    def test_change_password(self):
        user = ents.User.fake(is_verified=False)
        token = user.token_generate()
        user.change_password(token, 'abc123')
        assert not user.token_verify(token)
        assert user.password == 'abc123'
        assert user.is_verified

    def test_change_password_invalid_token(self):
        user = ents.User.fake(is_verified=False)
        with pytest.raises(InvalidToken):
            user.change_password('bad-token', 'abc123')

    def test_permissions_mapping(self):
        perm1 = ents.Permission.fake()
        perm2 = ents.Permission.fake()
        perm3 = ents.Permission.fake()
        perm4 = ents.Permission.fake()
        perm5 = ents.Permission.fake()

        bundle1 = ents.Bundle.fake()
        bundle2 = ents.Bundle.fake()
        bundle3 = ents.Bundle.fake()

        group1 = ents.Group.fake()
        group2 = ents.Group.fake()
        group3 = ents.Group.fake()

        user1 = ents.User.fake()
        user2 = ents.User.fake()

        # Directly assigned
        user1.permissions = [perm1]

        # Assigned via user bundle
        bundle1.permissions = [perm2]
        user1.bundles = [bundle1]

        # Assigned via group
        group1.permissions = [perm3]

        # Assigned via group bundle
        bundle2.permissions = [perm4]
        group1.bundles = [bundle2]
        user1.groups = [group1, group2]

        assert user1.get_all_permissions() == {perm1, perm2, perm3, perm4}
        assert user2.get_all_permissions() == set()

        user2.permissions = [perm1, perm2]
        group3.permissions = [perm2, perm3]
        bundle3.permissions = [perm1, perm5]
        group3.bundles = [bundle3]
        user2.groups = [group3]

        assert user1.get_all_permissions() == {perm1, perm2, perm3, perm4}
        assert user2.get_all_permissions() == {perm1, perm2, perm3, perm5}

        user1.is_superuser = True
        assert user1.get_all_permissions() == {perm1, perm2, perm3, perm4, perm5}

    def test_get_all_permission_tokens(self):
        ents.Permission.delete_cascaded()
        perm1 = ents.Permission.fake(token='perm-1')
        perm2 = ents.Permission.fake(token='perm-2')
        perm3 = ents.Permission.fake(token='perm-3')

        user = ents.User.fake(permissions=[perm1, perm2, perm3])

        assert user.get_all_permission_tokens() == {'perm-1', 'perm-2', 'perm-3'}

    def test_get_all_permission_tokens_cached(self):
        ents.Permission.delete_cascaded()
        perm1 = ents.Permission.fake(token='perm-1')
        perm2 = ents.Permission.fake(token='perm-2')
        perm3 = ents.Permission.fake(token='perm-3')

        user = ents.User.fake(permissions=[perm1, perm2])
        # trigger the cache storage
        assert user.get_all_permission_tokens() == {'perm-1', 'perm-2'}

        # permissions in cache go stale
        user.permissions = [perm1, perm2, perm3]
        db.session.commit()

        assert user.get_all_permission_tokens() == {'perm-1', 'perm-2'}

        # reset the cache
        delattr(user, '_permission_cache')

        assert user.get_all_permission_tokens() == {'perm-1', 'perm-2', 'perm-3'}

    def test_has_all_permissions(self):
        ents.Permission.delete_cascaded()
        perm1 = ents.Permission.fake(token='perm-1')
        perm2 = ents.Permission.fake(token='perm-2')
        ents.Permission.fake(token='perm-3')

        user = ents.User.fake(permissions=[perm1, perm2])

        assert user.has_all_permissions('perm-1', 'perm-2') is True
        assert user.has_all_permissions('perm-1', 'perm-3') is False
        assert user.has_all_permissions('perm-1') is True
        assert user.has_all_permissions('perm-3') is False

    def test_has_any_permission(self):
        ents.Permission.delete_cascaded()
        perm1 = ents.Permission.fake(token='perm-1')
        perm2 = ents.Permission.fake(token='perm-2')
        ents.Permission.fake(token='perm-3')

        user = ents.User.fake(permissions=[perm1, perm2])

        assert user.has_any_permission('perm-1', 'perm-2') is True
        assert user.has_any_permission('perm-1', 'perm-3') is True
        assert user.has_any_permission('perm-1') is True
        assert user.has_any_permission('perm-3') is False

    def test_superuser_update_resets_session_key(self):
        user = ents.User.fake(is_superuser=True)
        original_session_key = user.session_key

        ents.User.edit(user.id, is_superuser=False)
        db.session.expire(user)
        assert user.session_key != original_session_key

    def test_enabled_update_resets_session_key(self):
        user = ents.User.fake(is_enabled=True)
        original_session_key = user.session_key

        ents.User.edit(user.id, is_enabled=False)
        db.session.expire(user)
        assert user.session_key != original_session_key

    def test_permission_update_resets_session_key(self):
        perm1 = ents.Permission.fake(token='perm-1')
        perm2 = ents.Permission.fake(token='perm-2')

        user = ents.User.fake(permissions=[perm1])
        original_session_key = user.session_key

        ents.User.edit(user.id, permissions=[perm2])
        db.session.expire(user)
        assert user.session_key != original_session_key

    def test_group_update_resets_session_key(self):
        group1 = ents.Group.fake(name='group-1')
        group2 = ents.Group.fake(name='group-2')

        user = ents.User.fake(groups=[group1])
        original_session_key = user.session_key

        ents.User.edit(user.id, groups=[group2])
        db.session.expire(user)
        assert user.session_key != original_session_key

    def test_bundle_update_resets_session_key(self):
        bundle1 = ents.Bundle.fake(name='bundle-1')
        bundle2 = ents.Bundle.fake(name='bundle-2')

        user = ents.User.fake(bundles=[bundle1])
        original_session_key = user.session_key

        ents.User.edit(user.id, bundles=[bundle2])
        db.session.expire(user)
        assert user.session_key != original_session_key

    def test_non_permission_update_does_not_reset_session_key(self):
        user = ents.User.fake()
        original_session_key = user.session_key

        ents.User.edit(user.id, email='foo@bar.baz')
        db.session.expire(user)
        assert user.session_key == original_session_key

    def test_re_enabling_user_clears_disabled_utc(self):
        user = ents.User.fake(disabled_utc=arrow.utcnow(), is_enabled=False)
        ents.User.edit(user.id, is_enabled=True)
        db.session.expire(user)
        assert user.disabled_utc is None

    def test_re_enabling_user_does_not_clear_disabled_utc_if_changed(self):
        user = ents.User.fake(disabled_utc=arrow.utcnow().shift(days=-1), is_enabled=False)
        ents.User.edit(user.id, is_enabled=True, disabled_utc=arrow.utcnow())
        db.session.expire(user)
        assert user.disabled_utc

    def test_disabling_user_does_not_clear_disabled_utc(self):
        user = ents.User.fake(disabled_utc=arrow.utcnow(), is_enabled=True)
        ents.User.edit(user.id, is_enabled=False)
        db.session.expire(user)
        assert user.disabled_utc


class TestUserNoEmail(object):
    def setup_method(self):
        ents.UserNoEmail.delete_cascaded()

    @pytest.mark.parametrize('is_enabled, disabled_utc, is_active', [
        (True, None, True),
        (True, arrow.utcnow().shift(minutes=+5), True),
        (False, None, False),
        (True, arrow.utcnow().shift(minutes=-5), False),
    ])
    def test_is_active_python_attribute(self, is_enabled, disabled_utc, is_active):
        user = ents.UserNoEmail.fake(
            is_enabled=is_enabled,
            disabled_utc=disabled_utc,
        )
        assert user.is_active == is_active

    @pytest.mark.parametrize('is_enabled, disabled_utc, is_active', [
        (True, None, True),
        (True, arrow.utcnow().shift(minutes=+5), True),
        (False, None, False),
        (True, arrow.utcnow().shift(minutes=-5), False),
    ])
    def test_is_active_sql_expression(self, is_enabled, disabled_utc, is_active):
        ents.UserNoEmail.fake(
            username='name',
            is_enabled=is_enabled,
            disabled_utc=disabled_utc,
        )

        assert ents.UserNoEmail.query.filter_by(username='name', is_active=is_active).one()


class TestPermission(object):
    def setup_method(self):
        ents.Permission.delete_cascaded()

    def test_token_unique(self):
        ents.Permission.fake(token='some-permission')
        with pytest.raises(sa.exc.IntegrityError) as exc:
            # use `add` here instead of `fake`, because it is more helpful for the
            #   `fake` method to return the existing permission if there is a match
            ents.Permission.add(token='some-permission')

        assert 'unique' in str(exc.value).lower()


class TestBundle(object):
    def setup_method(self):
        ents.Bundle.delete_cascaded()

    def test_name_unique(self):
        ents.Bundle.fake(name='Bundle 1')
        with pytest.raises(sa.exc.IntegrityError) as exc:
            ents.Bundle.fake(name='Bundle 1')

        assert 'unique' in str(exc.value).lower()

    def test_permission_update_resets_user_session_keys(self):
        perm1 = ents.Permission.fake(token='perm-1')
        perm2 = ents.Permission.fake(token='perm-2')

        user = ents.User.fake()
        bundle = ents.Bundle.fake(permissions=[perm1], users=[user])
        original_session_key = user.session_key

        ents.Bundle.edit(bundle.id, permissions=[perm2])
        db.session.expire(user)
        assert user.session_key != original_session_key

    def test_permission_update_resets_group_user_session_keys(self):
        perm1 = ents.Permission.fake(token='perm-1')
        perm2 = ents.Permission.fake(token='perm-2')

        user = ents.User.fake()
        group = ents.Group.fake(users=[user])
        bundle = ents.Bundle.fake(permissions=[perm1], groups=[group])
        original_session_key = user.session_key

        ents.Bundle.edit(bundle.id, permissions=[perm2])
        db.session.expire(user)
        assert user.session_key != original_session_key

    def test_group_addition_resets_user_session_keys(self):
        user = ents.User.fake()
        group = ents.Group.fake(users=[user])
        bundle = ents.Bundle.fake()
        original_session_key = user.session_key

        ents.Bundle.edit(bundle.id, groups=[group])
        db.session.expire(user)
        assert user.session_key != original_session_key

    def test_group_removal_resets_user_session_keys(self):
        user = ents.User.fake()
        group = ents.Group.fake(users=[user])
        bundle = ents.Bundle.fake(groups=[group])
        original_session_key = user.session_key

        ents.Bundle.edit(bundle.id, groups=[])
        db.session.expire(user)
        assert user.session_key != original_session_key

    def test_user_addition_resets_user_session_keys(self):
        user = ents.User.fake()
        bundle = ents.Bundle.fake()
        original_session_key = user.session_key

        ents.Bundle.edit(bundle.id, users=[user])
        db.session.expire(user)
        assert user.session_key != original_session_key

    def test_user_removal_resets_user_session_keys(self):
        user = ents.User.fake()
        bundle = ents.Bundle.fake(users=[user])
        original_session_key = user.session_key

        ents.Bundle.edit(bundle.id, users=[])
        db.session.expire(user)
        assert user.session_key != original_session_key

    def test_bundle_removal_resets_user_session_keys(self):
        user = ents.User.fake()
        bundle = ents.Bundle.fake(users=[user])
        original_session_key = user.session_key
        ents.Bundle.delete(bundle.id)

        db.session.expire(user)
        assert user.session_key != original_session_key

    def test_bundle_removal_resets_group_session_keys(self):
        user = ents.User.fake()
        group = ents.Group.fake(users=[user])
        bundle = ents.Bundle.fake(groups=[group])
        original_session_key = user.session_key
        ents.Bundle.delete(bundle.id)

        db.session.expire(user)
        assert user.session_key != original_session_key

    def test_non_permission_update_does_not_reset_user_session_keys(self):
        user = ents.User.fake()
        bundle = ents.Bundle.fake(users=[user])
        original_session_key = user.session_key

        ents.Bundle.edit(bundle.id, name='foo')
        db.session.expire(user)
        assert user.session_key == original_session_key


class TestGroup(object):
    def setup_method(self):
        ents.Group.delete_cascaded()

    def test_name_unique(self):
        ents.Group.fake(name='Group 1')
        with pytest.raises(sa.exc.IntegrityError) as exc:
            ents.Group.fake(name='Group 1')

        assert 'unique' in str(exc.value).lower()

    def test_get_all_permissions(self):
        perm1 = ents.Permission.fake()
        perm2 = ents.Permission.fake()
        perm3 = ents.Permission.fake()

        bundle = ents.Bundle.fake()

        group1 = ents.Group.fake()
        group2 = ents.Group.fake()

        # Assigned directly
        group1.permissions = [perm1]

        # Assigned via bundle
        bundle.permissions = [perm2]
        group1.bundles = [bundle]

        assert group1.get_all_permissions() == {perm1, perm2}
        assert group2.get_all_permissions() == set()

        group2.bundles = [bundle]
        group2.permissions = [perm2, perm3]

        assert group1.get_all_permissions() == {perm1, perm2}
        assert group2.get_all_permissions() == {perm2, perm3}

    def test_permission_update_resets_user_session_keys(self):
        perm1 = ents.Permission.fake(token='perm-1')
        perm2 = ents.Permission.fake(token='perm-2')

        user = ents.User.fake()
        original_session_key = user.session_key
        group = ents.Group.fake(permissions=[perm1], users=[user])

        ents.Group.edit(group.id, permissions=[perm2])
        db.session.expire(user)
        assert user.session_key != original_session_key

    def test_bundle_update_resets_user_session_keys(self):
        bundle1 = ents.Bundle.fake(name='bundle-1')
        bundle2 = ents.Bundle.fake(name='bundle-2')

        user = ents.User.fake()
        original_session_key = user.session_key
        group = ents.Group.fake(bundles=[bundle1], users=[user])

        ents.Group.edit(group.id, bundles=[bundle2])
        db.session.expire(user)
        assert user.session_key != original_session_key

    def test_user_addition_resets_user_session_keys(self):
        user = ents.User.fake()
        original_session_key = user.session_key
        group = ents.Group.fake()

        ents.Group.edit(group.id, users=[user])
        db.session.expire(user)
        assert user.session_key != original_session_key

    def test_user_removal_resets_user_session_keys(self):
        user = ents.User.fake()
        original_session_key = user.session_key
        group = ents.Group.fake(users=[user])

        ents.Group.edit(group.id, users=[])
        db.session.expire(user)
        assert user.session_key != original_session_key

    def test_group_removal_resets_user_session_keys(self):
        user = ents.User.fake()
        group = ents.Group.fake(users=[user])
        original_session_key = user.session_key
        ents.Group.delete(group.id)

        db.session.expire(user)
        assert user.session_key != original_session_key

    def test_non_permission_update_does_not_reset_user_session_keys(self):
        user = ents.User.fake()
        group = ents.Group.fake(users=[user])
        original_session_key = user.session_key

        ents.Group.edit(group.id, name='foo')
        db.session.expire(user)
        assert user.session_key == original_session_key


class TestEntityRegistry(object):
    def test_bad_type(self):
        registry = entity_registry.EntityRegistry()
        with pytest.raises(entity_registry.RegistryError):
            registry.get_entity_cls('foo')

    def test_entity_not_defined(self):
        registry = entity_registry.EntityRegistry()
        with pytest.raises(entity_registry.RegistryError):
            registry.get_entity_cls('user')

    def test_register_entities(self):
        registry = entity_registry.EntityRegistry()

        @registry.register_user
        class TestingUser(object):
            pass

        @registry.register_permission
        class TestingPermission(object):
            pass

        @registry.register_bundle
        class TestingBundle(object):
            pass

        @registry.register_group
        class TestingGroup(object):
            pass

        assert registry.user_cls is TestingUser
        assert registry.permission_cls is TestingPermission
        assert registry.bundle_cls is TestingBundle
        assert registry.group_cls is TestingGroup

    def test_duplicate_registration(self):
        registry = entity_registry.EntityRegistry()

        @registry.register_user
        class TestingUser1(object):
            pass

        with pytest.raises(entity_registry.RegistryError) as exc:
            @registry.register_user
            class TestingUser2(object):
                pass

        assert str(exc.value) == 'Entity class already registered for user'

    def test_register_unknown_type(self):
        registry = entity_registry.EntityRegistry()

        class Foo(object):
            pass

        with pytest.raises(entity_registry.RegistryError) as exc:
            registry.register_entity('foo', Foo)

        assert str(exc.value) == 'Attempting to register unknown type foo'

    def test_register_nonclass(self):
        registry = entity_registry.EntityRegistry()

        with pytest.raises(entity_registry.RegistryError) as exc:
            @registry.register_user
            def testing_user():
                pass

        assert str(exc.value) == 'Entity must be a class'

        with pytest.raises(entity_registry.RegistryError) as exc:
            registry.register_user(ents.User.fake())

        assert str(exc.value) == 'Entity must be a class'

    def test_is_registered(self):
        registry = entity_registry.EntityRegistry()

        @registry.register_user
        class TestingUser(object):
            pass

        @registry.register_permission
        class TestingPermission(object):
            pass

        assert registry.is_registered('user') is True
        assert registry.is_registered('permission') is True
        assert registry.is_registered('bundle') is False
        assert registry.is_registered('group') is False


class TestPermissionsConditions:
    def setup_method(self):
        ents.Permission.delete_cascaded()
        ents.User.delete_cascaded()

    def test_no_conditions(self):
        with pytest.raises(ValueError):
            utils.PermissionCondition()

    def test_simple_string(self):
        user = ents.User.fake(
            permissions=[ents.Permission.fake(token='perm1')]
        )
        ents.Permission.fake(token='perm2')

        assert utils.has_any('perm1').check(user) is True
        assert utils.has_all('perm1').check(user) is True

        assert utils.has_any('perm2').check(user) is False
        assert utils.has_all('perm2').check(user) is False

    def test_callable(self):
        user1 = ents.User.fake(email='foo@bar.com')
        user2 = ents.User.fake(email='abc@123.com')

        def func(usr):
            return usr.email.endswith('@bar.com')

        assert utils.has_any(func).check(user1) is True
        assert utils.has_all(func).check(user1) is True

        assert utils.has_any(func).check(user2) is False
        assert utils.has_all(func).check(user2) is False

    def test_all(self):
        user = ents.User.fake(
            permissions=[
                ents.Permission.fake(token='perm1'),
                ents.Permission.fake(token='perm2'),
                ents.Permission.fake(token='perm3'),
            ]
        )
        ents.Permission.fake(token='perm4')

        assert utils.has_all('perm1').check(user) is True
        assert utils.has_all('perm1', 'perm2').check(user) is True
        assert utils.has_all('perm1', 'perm2', 'perm3').check(user) is True

        assert utils.has_all('perm4').check(user) is False
        assert utils.has_all('perm1', 'perm4').check(user) is False
        assert utils.has_all('perm1', 'perm2', 'perm4').check(user) is False

    def test_any(self):
        user = ents.User.fake(
            permissions=[ents.Permission.fake(token='perm1')]
        )
        ents.Permission.fake(token='perm2'),
        ents.Permission.fake(token='perm3'),
        ents.Permission.fake(token='perm4')

        assert utils.has_any('perm1').check(user) is True
        assert utils.has_any('perm1', 'perm2').check(user) is True
        assert utils.has_any('perm1', 'perm2', 'perm3').check(user) is True

        assert utils.has_any('perm2').check(user) is False
        assert utils.has_any('perm2', 'perm3').check(user) is False
        assert utils.has_any('perm2', 'perm3', 'perm4').check(user) is False

    def test_nested(self):
        user = ents.User.fake(
            permissions=[
                ents.Permission.fake(token='perm1'),
                ents.Permission.fake(token='perm2'),
                ents.Permission.fake(token='perm3'),
            ]
        )
        ents.Permission.fake(token='perm4')

        condition = utils.has_any('perm4', utils.has_all('perm1', 'perm2'))
        assert condition.check(user) is True

        condition = utils.has_all(utils.has_any('perm1', 'perm2'), 'perm4')
        assert condition.check(user) is False

        condition = utils.has_all(utils.has_any('perm4', lambda _: True), 'perm1')
        assert condition.check(user) is True

        condition = utils.has_all(utils.has_any('perm4', lambda _: False), 'perm1')
        assert condition.check(user) is False


"""class TestPerformance(object):
    # check how long the SA events add to the process
    def test_performance(self):
        import time
        start = time.time()
        for _ in range(1000):
            ents.User.fake()
            ents.Group.fake()
            ents.Bundle.fake()
        assert False, time.time() - start
"""
