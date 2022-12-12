import sys
from unittest import mock

import flask
import flask_login
import pytest

from keg_auth.libs.navigation import NavItem, NavURL

from keg_auth_ta import views

nav_menu = NavItem(
    NavItem('Home', NavURL('public.home', arg1='foo')),
    NavItem(
        'Nesting',
        NavItem('Secret1', NavURL('private.secret1')),
        NavItem('Secret1 Class', NavURL('private.secret1-class')),
    ),
    NavItem('Permissions On Stock Methods', NavURL('private.secret2')),
    NavItem('Permissions On Methods', NavURL('private.someroute')),
    NavItem('Permissions On Class And Method', NavURL('private.secret4')),
    NavItem('Permissions On NavURL',
            NavURL(
                'private.secret3', requires_permissions='permission3'
            )),
    NavItem('User Manage', NavURL('auth.user:add')),
)


class TestViewMetaInfo(object):
    @classmethod
    def setup_class(cls):
        # cause the navigation nodes to walk, assigning defining classes to the subnodes
        nav_menu.is_permitted

    def test_decorated_class_meta_user(self):
        assert views.Secret1Class.__keg_auth_requires_user__

    def test_decorated_class_meta_permissions(self):
        assert views.Secret3.__keg_auth_requires_user__
        assert views.Secret3.__keg_auth_requires_permissions__

    def test_decorated_method_meta_user(self):
        assert views.secret1.__keg_auth_requires_user__
        assert views.secret1.__keg_auth_parent_class__ is None

    def test_decorated_bound_method_meta_permissions(self):
        assert views.Secret2.get.__keg_auth_requires_user__
        assert views.Secret2.get.__keg_auth_requires_permissions__
        if sys.version_info[0] != 2:
            assert views.Secret2.get.__keg_auth_parent_class__ is views.Secret2
        else:
            assert views.Secret2.get.im_class is views.Secret2  # pragma: no cover

    def test_decorated_blueprint(self):
        assert views.protected_bp.__keg_auth_requires_user__
        assert views.protected_bp.__keg_auth_requires_permissions__


class TestNavItem(object):
    """ Test node permission logic

        Tests of node permissions are user-oriented, so we have to run these in a request context
    """

    def setup_method(self):
        self.Permission = flask.current_app.auth_manager.entity_registry.permission_cls
        self.Permission.delete_cascaded()

    def test_no_args(self):
        with pytest.raises(
            Exception, match='must provide a NavURL or a list of NavItems'
        ):
            NavItem()

    def test_node_invalid_endpoint(self):
        with pytest.raises(
            Exception, match='Endpoint pink_unicorns in navigation is not registered'
        ):
            NavItem('Foo', NavURL('pink_unicorns')).is_permitted

    def test_nav_group_not_assigned(self):
        node = NavItem('Foo', NavURL('public.home'))
        assert not node.nav_group

    def test_nav_group_auto_assigned(self):
        node = NavItem(
            NavItem(
                'This Beard Stays',
                NavItem('Foo2', NavURL('public.home')),
            ),
            NavItem(
                'Bar',
                NavItem('Bar2', NavURL('private.secret1')),
            )
        )
        assert node.sub_nodes[0].nav_group == 'this-beard-stays'

    def test_nav_group_manual_preserved(self):
        node = NavItem(
            NavItem(
                'Foo',
                NavItem('Foo2', NavURL('public.home')),
                nav_group='this-beard-stays'
            ),
            NavItem(
                'Bar',
                NavItem('Bar2', NavURL('private.secret1')),
            ),
        )
        assert node.sub_nodes[0].nav_group == 'this-beard-stays'

    def test_current_route_not_exists(self):
        node = NavItem('Foo', NavURL('public.home'))

        with flask.current_app.test_request_context('/some-random-route'):
            assert not node.has_current_route

    def test_current_route_not_matched(self):
        node = NavItem('Foo', NavURL('public.home'))

        with flask.current_app.test_request_context('/secret1'):
            assert not node.has_current_route

    def test_current_route_matched(self):
        node = NavItem('Foo', NavURL('public.home'))

        with flask.current_app.test_request_context('/'):
            assert node.has_current_route

    def test_current_route_matched_nested(self):
        node = NavItem(
            NavItem(
                'Foo',
                NavItem('Foo2', NavURL('public.home')),
            ),
            NavItem(
                'Bar',
                NavItem('Bar2', NavURL('private.secret1')),
            )
        )

        with flask.current_app.test_request_context('/'):
            assert node.has_current_route
            assert node.sub_nodes[0].has_current_route
            assert not node.sub_nodes[1].has_current_route

    def test_leaf_no_requirement(self):
        node = NavItem('Foo', NavURL('public.home'))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert node.is_permitted

            user = flask.current_app.auth_manager.entity_registry.user_cls.fake()
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert node.is_permitted

    def test_leaf_method_requires_user(self):
        node = NavItem('Foo', NavURL('private.secret1'))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.is_permitted

            user = flask.current_app.auth_manager.entity_registry.user_cls.fake()
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert node.is_permitted

    @pytest.mark.parametrize('endpoint', ['private.secret1-class', 'private.secret1-flask-class'])
    def test_leaf_class_requires_user(self, endpoint):
        node = NavItem('Foo', NavURL(endpoint))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.is_permitted

            user = flask.current_app.auth_manager.entity_registry.user_cls.fake()
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert node.is_permitted

    def test_leaf_method_requires_permissions(self):
        node = NavItem('Foo', NavURL('private.secret2'))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.is_permitted

            user = flask.current_app.auth_manager.entity_registry.user_cls.fake()
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert not node.is_permitted

            perm1 = self.Permission.fake(token='permission1')
            perm2 = self.Permission.fake(token='permission2')
            user = flask.current_app.auth_manager.entity_registry.user_cls.fake(
                permissions=[perm1, perm2])
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert node.is_permitted

    def test_leaf_method_requires_callable_permissions(self):
        node = NavItem('Foo', NavURL('private.secret_callable'))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.is_permitted

            user = flask.current_app.auth_manager.entity_registry.user_cls.fake()
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert not node.is_permitted

            flask_login.current_user.email = 'foo@bar.baz'
            node.clear_authorization(user.get_id())
            assert node.is_permitted

    @pytest.mark.parametrize('endpoint', ['private.secret3', 'private.secret-flask'])
    def test_leaf_class_requires_permissions(self, endpoint):
        node = NavItem('Foo', NavURL(endpoint))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.is_permitted

            user = flask.current_app.auth_manager.entity_registry.user_cls.fake()
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert not node.is_permitted

            perm1 = self.Permission.fake(token='permission1')
            perm2 = self.Permission.fake(token='permission2')
            user = flask.current_app.auth_manager.entity_registry.user_cls.fake(
                permissions=[perm1, perm2])
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert node.is_permitted

    def test_leaf_class_requires_callable_permissions(self):
        node = NavItem('Foo', NavURL('callable_protected.callable-protected-class'))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.is_permitted

            user = flask.current_app.auth_manager.entity_registry.user_cls.fake()
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert not node.is_permitted

            user.class_pass = True
            user.blueprint_pass = True
            node.clear_authorization(user.get_id())
            assert node.is_permitted

    @pytest.mark.parametrize('endpoint', ['private.secret4', 'private.secret-flask4'])
    def test_leaf_method_and_class_both_require(self, endpoint):
        node = NavItem('Foo', NavURL(endpoint))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.is_permitted

            user = flask.current_app.auth_manager.entity_registry.user_cls.fake()
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert not node.is_permitted

            perm1 = self.Permission.fake(token='permission1')
            perm2 = self.Permission.fake(token='permission2')
            user = flask.current_app.auth_manager.entity_registry.user_cls.fake(
                permissions=[perm1])
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert not node.is_permitted

            user = flask.current_app.auth_manager.entity_registry.user_cls.fake(
                permissions=[perm2])
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert not node.is_permitted

            user = flask.current_app.auth_manager.entity_registry.user_cls.fake(
                permissions=[perm1, perm2])
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert node.is_permitted

    def test_leaf_specifies_own_requirement(self):
        node = NavItem('Foo', NavURL('private.secret2', requires_permissions='permission1'))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.is_permitted

            user = flask.current_app.auth_manager.entity_registry.user_cls.fake()
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert not node.is_permitted

            perm1 = self.Permission.fake(token='permission1')
            user = flask.current_app.auth_manager.entity_registry.user_cls.fake(
                permissions=[perm1])
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert node.is_permitted

    def test_leaf_method_blueprint_requires_permissions(self):
        node = NavItem('Foo', NavURL('protected.protected_method'))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.is_permitted

            user = flask.current_app.auth_manager.entity_registry.user_cls.fake()
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert not node.is_permitted

            perm1 = self.Permission.fake(token='permission1')
            user = flask.current_app.auth_manager.entity_registry.user_cls.fake(
                permissions=[perm1])
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert node.is_permitted

    def test_leaf_class_blueprint_requires_permissions(self):
        node = NavItem('Foo', NavURL('protected.protected-class'))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.is_permitted

            user = flask.current_app.auth_manager.entity_registry.user_cls.fake()
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert not node.is_permitted

            perm1 = self.Permission.fake(token='permission1')
            user = flask.current_app.auth_manager.entity_registry.user_cls.fake(
                permissions=[perm1])
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert node.is_permitted

    def test_stem_requirement_from_subnode(self):
        node = NavItem('Menu', NavItem('Foo', NavURL('private.secret1-class')))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.is_permitted

            user = flask.current_app.auth_manager.entity_registry.user_cls.fake()
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert node.is_permitted

    def test_stem_requirement_from_subnode_two_level(self):
        node = NavItem('Menu', NavItem('Menu2', NavItem('Foo', NavURL('private.secret1-class'))))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.is_permitted

            user = flask.current_app.auth_manager.entity_registry.user_cls.fake()
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert node.is_permitted

    def test_permitted_subnodes(self):
        perm1 = self.Permission.fake(token='permission1')
        node = NavItem(
            'Menu',
            NavItem('Index', NavURL('public.home', requires_permissions='permission2')),
            NavItem(
                'Submenu',
                NavItem('Profile', NavURL('private.secret1', requires_permissions='permission1')),
                NavItem('Control Panel', NavURL('private.secret2', requires_permissions='permission2')),  # noqa
                NavItem('Accounts', NavURL('private.secret3', requires_permissions='permission1')),
            ),
            NavItem('History', NavURL('private.secret4', requires_permissions='permission2')),
        )
        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.permitted_sub_nodes

            user = flask.current_app.auth_manager.entity_registry.user_cls.fake(
                permissions=[perm1])
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert len(node.permitted_sub_nodes) == 1
            assert node.permitted_sub_nodes[0].label == 'Submenu'

            assert len(node.permitted_sub_nodes[0].permitted_sub_nodes) == 2
            assert node.permitted_sub_nodes[0].permitted_sub_nodes[0].label == 'Profile'
            assert node.permitted_sub_nodes[0].permitted_sub_nodes[1].label == 'Accounts'

    def test_per_user_menu_items(self):
        node = NavItem('Foo', NavURL('private.secret2', requires_permissions='permission1'))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.is_permitted

            user = flask.current_app.auth_manager.entity_registry.user_cls.fake()
            flask_login.login_user(user)
            assert not node.is_permitted

            perm1 = self.Permission.fake(token='permission1')
            user = flask.current_app.auth_manager.entity_registry.user_cls.fake(
                permissions=[perm1])
            flask_login.login_user(user)
            assert node.is_permitted

    @mock.patch('keg_auth.libs.navigation.is_lazy_string', return_value=True)
    def test_lazy_string_label(self, _):
        # Pass a non-string label so is_lazy_string gets called.
        label = 12
        node = NavItem(label, NavURL('public.home'))
        assert node.label == label

    def test_logout_presence(self):
        node = NavItem('Foo', NavURL('auth.logout'))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.is_permitted

            user = flask.current_app.auth_manager.entity_registry.user_cls.fake()
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert node.is_permitted

    def test_login_presence(self):
        node = NavItem('Foo', NavURL('auth.login', requires_anonymous=True))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert node.is_permitted

            user = flask.current_app.auth_manager.entity_registry.user_cls.fake()
            flask_login.login_user(user)
            node.clear_authorization(user.get_id())
            assert not node.is_permitted
