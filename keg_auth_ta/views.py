import logging

import flask
import flask_login
import keg.web

from keg_auth import make_blueprint, requires_permissions, has_any, has_all
from keg_auth_ta.extensions import csrf

log = logging.getLogger(__name__)

public_bp = flask.Blueprint('public', __name__)
private_bp = flask.Blueprint('private', __name__)
auth_bp = make_blueprint(__name__)

blueprints = public_bp, private_bp, auth_bp

# Exempt from CSRF or we have problems with Secret2.post.
csrf.exempt(private_bp)


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


class Secret2(keg.web.BaseView):
    blueprint = private_bp

    @requires_permissions(has_any('permission1', 'permission2'))
    def get(self):
        return 'secret2'

    @requires_permissions(has_all('permission1', 'permission2'))
    def post(self):
        return 'secret2 post'

    @requires_permissions('permission1')
    def put(self):
        return 'secret2 put'

    @requires_permissions('permission1')
    def patch(self):
        return 'secret2 patch'

    @requires_permissions('permission1')
    def delete(self):
        return 'secret2 delete'

    @requires_permissions('permission1')
    def options(self):
        return 'secret2 options'


@requires_permissions(has_all('permission1', 'permission2'))
class Secret3(keg.web.BaseView):
    blueprint = private_bp

    def get(self):
        return 'secret3'
