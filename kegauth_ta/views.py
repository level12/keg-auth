import logging

import flask
import flask_login
import keg.web
from kegauth.views import AuthenticatedView, make_blueprint

log = logging.getLogger(__name__)

public_bp = flask.Blueprint('public', __name__)
private_bp = flask.Blueprint('private', __name__)
auth_bp = make_blueprint(__name__)

blueprints = public_bp, private_bp, auth_bp


class Home(keg.web.BaseView):
    blueprint = public_bp
    url = '/'
    template_name = 'home.html'

    def get(self):
        pass


@private_bp.route('/secret1')
@flask_login.login_required
def secret1():
    return 'secret1'


class Secret2(AuthenticatedView):
    blueprint = private_bp

    def get(self):
        return 'secret2'
