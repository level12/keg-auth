import logging

import flask
import keg.web

from keg_auth import make_blueprint, requires_permissions, requires_user, has_any, has_all
from keg_auth_ta.extensions import csrf, auth_manager

log = logging.getLogger(__name__)


@requires_permissions('permission1')
class ProtectedBlueprint(flask.Blueprint):
    def on_authentication_failure(self):
        flask.abort(405)


@requires_user()
class ProtectedBlueprint2(flask.Blueprint):
    pass


public_bp = flask.Blueprint('public', __name__)
private_bp = flask.Blueprint('private', __name__)
protected_bp = ProtectedBlueprint('protected', __name__)
protected_bp2 = ProtectedBlueprint2('protected2', __name__)
auth_bp = make_blueprint(__name__, auth_manager)

blueprints = public_bp, private_bp, protected_bp, protected_bp2, auth_bp

# Exempt from CSRF or we have problems with Secret2.post.
csrf.exempt(private_bp)


class Home(keg.web.BaseView):
    blueprint = public_bp
    url = '/'
    template_name = 'home.html'

    def get(self):
        pass


@private_bp.route('/secret1')
@requires_user
def secret1():
    return 'secret1'


@requires_user()
class Secret1Class(keg.web.BaseView):
    """ Show class decorator usage of requires_user, and also that the decorator works with or
        without ()
    """
    blueprint = private_bp

    def get(self):
        return 'secret1-class'

    def on_authentication_failure(self):
        flask.abort(405)


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


class Secret3Sub(Secret3):
    def get(self):
        return 'secret3-sub'


@requires_permissions('permission1')
class Secret4(keg.web.BaseView):
    blueprint = private_bp

    @requires_permissions('permission2')
    def get(self):
        return 'secret4'

    def on_authorization_failure(self):
        flask.abort(405)


@private_bp.route('/secret-nested')
@requires_permissions(has_any(has_all('permission1', 'permission2'), 'permission3'))
def secret_nested():
    return 'secret_nested'


@private_bp.route('/secret-callable')
@requires_permissions(lambda user: user.email == 'foo@bar.baz')
def secret_callable():
    return 'secret_callable'


@private_bp.route('/secret-nested-callable')
@requires_permissions(has_any('permission1',
                              lambda user: user.email == 'foo@bar.baz'))
def secret_nested_callable():
    return 'secret_nested_callable'


class SecretNavURLOnClass(keg.web.BaseView):
    blueprint = private_bp

    @private_bp.route('/secret-route-on-class')
    @requires_permissions('permission1')
    def someroute(self):
        return 'secret-route-on-class'


class ProtectedClass(keg.web.BaseView):
    blueprint = protected_bp

    def get(self):
        return 'protected-class'


class ProtectedClass2(keg.web.BaseView):
    blueprint = protected_bp2

    def get(self):
        return 'protected-class2'


@protected_bp.route('/protected-method')
def protected_method():
    return 'protected-method'


@private_bp.route('/jwt-required')
@requires_user
def jwt_required():
    return 'jwt-required'


@private_bp.route('/custom-auth-failure')
@requires_user(on_authentication_failure=lambda: flask.abort(400))
def custom_auth_failure():
    return 'custom-auth-failure'


@private_bp.route('/custom-perm-failure')
@requires_permissions('permission1', on_authorization_failure=lambda: flask.abort(400))
def custom_perm_failure():
    return 'custom-perm-failure'
