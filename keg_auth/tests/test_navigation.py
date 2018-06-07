import flask
import flask_login

from keg_auth.libs.navigation import Node, Route
from keg_auth.model import entity_registry

from keg_auth_ta import views

nav_menu = Node(
    None,
    Node('Home', Route('public.home')),
    Node(
        'Nesting',
        Node('Secret1', Route('private.secret1')),
        Node('Secret1 Class', Route('private.secret1-class')),
    ),
    Node('Permissions On Stock Methods', Route('private.secret2')),
    Node('Permissions On Methods', Route('private.someroute')),
    Node('Permissions On Class And Method', Route('private.secret4')),
    Node('Permissions On Route',
         Route(
             'private.secret3', requires_permissions='permission3'
         )),
    Node('User Manage', Route('auth.user:add')),
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
        assert views.Secret2.get.__keg_auth_parent_class__ is views.Secret2


class TestNode(object):
    """ Test node permission logic

        Tests of node permissions are user-oriented, so we have to run these in a request context
    """

    def setup(self):
        self.Permission = entity_registry.registry.permission_cls
        self.Permission.delete_cascaded()

    def test_leaf_no_requirement(self):
        node = Node('Foo', Route('public.home'))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert node.is_permitted

            user = entity_registry.registry.user_cls.testing_create()
            flask_login.login_user(user)
            node.clear_authorization()
            assert node.is_permitted

    def test_leaf_method_requires_user(self):
        node = Node('Foo', Route('private.secret1'))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.is_permitted

            user = entity_registry.registry.user_cls.testing_create()
            flask_login.login_user(user)
            node.clear_authorization()
            assert node.is_permitted

    def test_leaf_class_requires_user(self):
        node = Node('Foo', Route('private.secret1-class'))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.is_permitted

            user = entity_registry.registry.user_cls.testing_create()
            flask_login.login_user(user)
            node.clear_authorization()
            assert node.is_permitted

    def test_leaf_method_requires_permissions(self):
        node = Node('Foo', Route('private.secret2'))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.is_permitted

            user = entity_registry.registry.user_cls.testing_create()
            flask_login.login_user(user)
            node.clear_authorization()
            assert not node.is_permitted

            perm1 = self.Permission.testing_create(token='permission1')
            perm2 = self.Permission.testing_create(token='permission2')
            user = entity_registry.registry.user_cls.testing_create(permissions=[perm1, perm2])
            flask_login.login_user(user)
            node.clear_authorization()
            assert node.is_permitted

    def test_leaf_class_requires_permissions(self):
        node = Node('Foo', Route('private.secret3'))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.is_permitted

            user = entity_registry.registry.user_cls.testing_create()
            flask_login.login_user(user)
            node.clear_authorization()
            assert not node.is_permitted

            perm1 = self.Permission.testing_create(token='permission1')
            perm2 = self.Permission.testing_create(token='permission2')
            user = entity_registry.registry.user_cls.testing_create(permissions=[perm1, perm2])
            flask_login.login_user(user)
            node.clear_authorization()
            assert node.is_permitted

    def test_leaf_method_and_class_both_require(self):
        node = Node('Foo', Route('private.secret4'))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.is_permitted

            user = entity_registry.registry.user_cls.testing_create()
            flask_login.login_user(user)
            node.clear_authorization()
            assert not node.is_permitted

            perm1 = self.Permission.testing_create(token='permission1')
            perm2 = self.Permission.testing_create(token='permission2')
            user = entity_registry.registry.user_cls.testing_create(permissions=[perm1])
            flask_login.login_user(user)
            node.clear_authorization()
            assert not node.is_permitted

            user = entity_registry.registry.user_cls.testing_create(permissions=[perm2])
            flask_login.login_user(user)
            node.clear_authorization()
            assert not node.is_permitted

            user = entity_registry.registry.user_cls.testing_create(permissions=[perm1, perm2])
            flask_login.login_user(user)
            node.clear_authorization()
            assert node.is_permitted

    def test_leaf_specifies_own_requirement(self):
        node = Node('Foo', Route('private.secret2', requires_permissions='permission1'))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.is_permitted

            user = entity_registry.registry.user_cls.testing_create()
            flask_login.login_user(user)
            node.clear_authorization()
            assert not node.is_permitted

            perm1 = self.Permission.testing_create(token='permission1')
            user = entity_registry.registry.user_cls.testing_create(permissions=[perm1])
            flask_login.login_user(user)
            node.clear_authorization()
            assert node.is_permitted

    def test_stem_requirement_from_subnode(self):
        node = Node('Menu', Node('Foo', Route('private.secret1-class')))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.is_permitted

            user = entity_registry.registry.user_cls.testing_create()
            flask_login.login_user(user)
            node.clear_authorization()
            assert node.is_permitted

    def test_stem_requirement_from_subnode_two_level(self):
        node = Node('Menu', Node('Menu2', Node('Foo', Route('private.secret1-class'))))

        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.is_permitted

            user = entity_registry.registry.user_cls.testing_create()
            flask_login.login_user(user)
            node.clear_authorization()
            assert node.is_permitted

    def test_permitted_subnodes(self):
        perm1 = self.Permission.testing_create(token='permission1')
        node = Node(
            'Menu',
            Node('Index', Route('public.home', requires_permissions='permission2')),
            Node(
                'Submenu',
                Node('Profile', Route('private.secret1', requires_permissions='permission1')),
                Node('Control Panel', Route('private.secret2', requires_permissions='permission2')),
                Node('Accounts', Route('private.secret3', requires_permissions='permission1')),
            ),
            Node('History', Route('private.secret4', requires_permissions='permission2')),
        )
        with flask.current_app.test_request_context('/'):
            flask_login.logout_user()
            assert not node.permitted_sub_nodes

            user = entity_registry.registry.user_cls.testing_create(permissions=[perm1])
            flask_login.login_user(user)
            node.clear_authorization()
            assert len(node.permitted_sub_nodes) == 1
            assert node.permitted_sub_nodes[0].label == 'Submenu'

            assert len(node.permitted_sub_nodes[0].permitted_sub_nodes) == 2
            assert node.permitted_sub_nodes[0].permitted_sub_nodes[0].label == 'Profile'
            assert node.permitted_sub_nodes[0].permitted_sub_nodes[1].label == 'Accounts'
