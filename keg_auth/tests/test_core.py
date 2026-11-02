from unittest import mock

import flask
import flask_login
import freezegun
import arrow
from keg_auth.core import fix_session_cookies, update_last_login
from keg_auth_ta.model import entities as ents


class TestUpdateLastLogin(object):

    @freezegun.freeze_time("2018-10-01 15:00:00")
    def test_it_will_update_last_login(self):
        u = ents.User.fake(email=u"test@bar.com", last_login_utc=None)
        update_last_login(flask.current_app, u)
        ents.db.session.remove()
        u = ents.User.get_by(email=u"test@bar.com")
        assert u.last_login_utc == arrow.utcnow()


class TestSessionClear:
    def test_session_cleared_after_signing_out(self):
        with flask.current_app.test_request_context():
            flask.session['foo'] = 'bar'
            assert 'foo' in list(flask.session)
            flask_login.logout_user()
            assert len(list(flask.session)) == 0

    @mock.patch.dict('flask.current_app.config', {'KEGAUTH_LOGOUT_CLEAR_SESSION': False})
    def test_session_not_cleared_after_signing_out(self):
        with flask.current_app.test_request_context():
            flask.session['foo'] = 'bar'
            assert 'foo' in list(flask.session)
            flask_login.logout_user()
            assert len(list(flask.session)) == 1


def test_fix_session_cookies():
    with flask.current_app.test_request_context():
        with mock.patch(
            'keg_auth.core.get_cookie_values', autospec=True, spec_set=True
        ) as m_cookies:
            with mock.patch('flask.abort', autospec=True, spec_set=True) as m_abort:
                m_cookies.return_value = ['FoObAr', 'BarFOo']
                fix_session_cookies(flask.current_app)
                m_abort.assert_called_once()
