from kegauth_ta.model import entities as ents


class TestUser:
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

