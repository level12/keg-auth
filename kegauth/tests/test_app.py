import flask
import flask_webtest
from kegauth.testing import AuthTests  # noqa

from kegauth_ta.app import KegAuthTestApp
from kegauth_ta.model import entities as ents


def setup_module():
    KegAuthTestApp.testing_prep()


class TestAuthIntegration(AuthTests):
    user_ent = ents.User
