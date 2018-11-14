import flask
import freezegun
import arrow
from keg_auth.core import update_last_login
from keg_auth_ta.model import entities as ents


class TestUpdateLastLogin(object):

    @freezegun.freeze_time("2018-10-01 15:00:00")
    def test_it_will_update_last_login(self):
        u = ents.User.testing_create(email=u"test@bar.com", last_login_utc=None)
        update_last_login(flask.current_app, u)
        ents.db.session.remove()
        u = ents.User.get_by(email=u"test@bar.com")
        assert u.last_login_utc == arrow.utcnow()
