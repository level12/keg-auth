import inspect
import sys

from blazeutils.strings import simplify_string
import flask
import flask_login

from keg_auth.extensions import lazy_gettext as _
from keg_auth.model.utils import has_permissions

try:
    from speaklater import is_lazy_string
except ImportError:
    is_lazy_string = lambda value: False  # noqa: E731


def get_defining_class(func):
    if inspect.isclass(func):
        return

    if sys.version_info[0] == 2:
        return getattr(func, 'im_class', None)  # pragma: no cover

    if inspect.isfunction(func):
        parse_def = func.__qualname__.split('.<locals>', 1)[0].rsplit('.', 1)
        if len(parse_def) == 1:
            # looks like a method without a class
            return
        return getattr(inspect.getmodule(func), parse_def[0])


class NavURL(object):
    """Wraps url_for with permission-checking to determine if user should see a route.

    Endpoint is checked for user/permission requirements.
    - method/class/blueprint permissions from decorators (preferred in most cases)
    - `requires_permissions` kwarg specifies conditions and disregards the decorators
    - `requires_anonymous` kwarg forces nav for only unauthenticated users

    Note that permission requirements are checked at all levels of the view hierarchy as
    needed: method, class, and blueprint.
    """
    def __init__(self, route_string, *args, **kwargs):
        self.route_string = route_string
        self.route_args = args
        self.route_kwargs = kwargs
        self.requires_permissions = kwargs.pop('requires_permissions', None)
        self.requires_anonymous = kwargs.pop('requires_anonymous', None)

    @property
    def url(self):
        return flask.url_for(self.route_string, *self.route_args, **self.route_kwargs)

    @property
    def is_permitted(self):
        """ Check permitted status of this route for the current user """
        # simplest case: route has requirements directly assigned
        if self.requires_permissions:
            if not flask_login.current_user or not flask_login.current_user.is_authenticated:
                return False
            return has_permissions(
                self.requires_permissions,
                flask_login.current_user
            )

        # other simple case: route is forced to show only anonymous users
        if self.requires_anonymous:
            return not bool(
                flask_login.current_user
                and flask_login.current_user.is_authenticated
            )

        # otherwise, we need to find the view for the route. In that case, both the route and its
        #   defining class (if any) may (or may not) have requirements to check.
        # the following checks are ANDed, so return False if anything fails
        view_obj = flask.current_app.view_functions.get(self.route_string)
        if not view_obj:
            raise Exception(
                _('Endpoint {} in navigation is not registered').format(self.route_string)
            )

        def check_auth(obj):
            if obj is None:
                return True

            if (
                getattr(obj, '__keg_auth_requires_user__', False) and (
                    not flask_login.current_user
                    or not flask_login.current_user.is_authenticated
                )
            ):
                return False

            if (
                getattr(obj, '__keg_auth_requires_permissions__', False)
                and not has_permissions(
                    obj.__keg_auth_requires_permissions__,
                    flask_login.current_user
                )
            ):
                return False

            return True

        def fetch_parent_class(view_obj):
            parent_class = getattr(
                view_obj, 'im_class',
                getattr(view_obj, '__keg_auth_parent_class__', None)
            )
            if not parent_class and not hasattr(view_obj, '__keg_auth_parent_class__'):
                obj = view_obj

                if hasattr(obj, '__keg_auth_original_function__'):
                    # the target method has been wrapped by a keg auth decorator, so we need
                    #   to inspect the original method to find the parent class (if any)
                    obj = obj.__keg_auth_original_function__

                view_obj.__keg_auth_parent_class__ = get_defining_class(obj)
                parent_class = view_obj.__keg_auth_parent_class__
            return parent_class

        def fetch_blueprint():
            return flask.current_app.blueprints.get(self.route_string.split('.', 1)[0], None)

        if hasattr(view_obj, 'view_class'):
            # class got wrapped with flask's as_view - get the original view to see what
            #   requirements are stored there
            view_obj = view_obj.view_class

        if inspect.isclass(view_obj) and hasattr(view_obj, 'get'):
            # view class has an action method likely to be called via a navigation link
            if sys.version_info[0] != 2:
                view_obj.get.__keg_auth_parent_class__ = view_obj
            view_obj = view_obj.get

        # make sure defining class is assigned (if any). We need to know this in order to
        #   check requirements at the class level
        parent_class = fetch_parent_class(view_obj)

        blueprint = fetch_blueprint()

        return check_auth(view_obj) and check_auth(parent_class) and check_auth(blueprint)


class NavItem(object):
    """Defines a menu item or structure of a menu.

    Example::

        my_menu = NavItem(
            NavItem(
                'Admin',
                NavItem('Users', NavURL('auth.user:list')),
                NavItem('Groups', NavURL('auth.group:list')),
                nav_group='admin',
                icon_class='fas fa-briefcase',
                class_='my-menu-group'
            ),
            NavItem(
                'Reports',
                NavItem('Frequency', NavURL('frequency-report'), code='frequency'),
                NavItem('Financial', NavURL('money-report', requires_permissions='secret-perm'))
            )
        )

    """
    class NavItemType(object):
        STEM = 0
        LEAF = 1

    def __init__(self, *args, nav_group=None, icon_class=None, class_=None, code=None):
        self.label = None
        if len(args) and (isinstance(args[0], str) or is_lazy_string(args[0])):
            self.label = args[0]
            args = args[1:]
        self.route = None
        self.sub_nodes = None
        self.nav_group = nav_group
        self.icon_class = icon_class
        self.class_ = class_
        self.code = code

        # cache permission-related items
        self._is_permitted = {}
        self._permitted_sub_nodes = {}

        if len(args) == 0:
            raise Exception(_('must provide a NavURL or a list of NavItems'))

        if isinstance(args[0], NavURL):
            self.route = args[0]
            if len(args) > 1:
                args = args[1:]
            else:
                return

        if len(args):
            self.sub_nodes = args
            if not self.nav_group:
                self.nav_group = simplify_string(self.label or '__root__')

    def clear_authorization(self, session_key):
        """Reset cached authorization in this and all subnodes for the given session key."""
        self._is_permitted.pop(session_key, None)
        self._permitted_sub_nodes.pop(session_key, None)
        for sub_node in (self.sub_nodes or []):
            sub_node.clear_authorization(session_key)

    @property
    def node_type(self):
        """Return type NavItemType indicating whether this node is at the end of the structure."""
        if self.sub_nodes:
            return NavItem.NavItemType.STEM
        return NavItem.NavItemType.LEAF

    @property
    def is_permitted(self):
        """Compute/cache authorization from permission conditions, and return bool."""
        current_user = flask_login.current_user
        session_key = current_user.get_id() if current_user else None
        if self._is_permitted.get(session_key) is None:
            if self.node_type == NavItem.NavItemType.LEAF:
                # checks the route for requirements, or the target view/class
                self._is_permitted[session_key] = self.route.is_permitted
            else:
                # find a subnode that is permitted
                self._is_permitted[session_key] = (len(self.permitted_sub_nodes) > 0)

        return self._is_permitted.get(session_key)

    @property
    def permitted_sub_nodes(self):
        """Return list of subnodes accessible to current user."""
        current_user = flask_login.current_user
        session_key = current_user.get_id() if current_user else None
        if self._permitted_sub_nodes.get(session_key) is None:
            self._permitted_sub_nodes[session_key] = [
                node for node in (self.sub_nodes or []) if node.is_permitted
            ]

        return self._permitted_sub_nodes.get(session_key)

    @property
    def has_current_route(self):
        """Returns true if current request matches this nav node."""
        if self.route:
            return self.route.route_string == flask.request.endpoint
        else:
            for node in self.permitted_sub_nodes:
                if node.has_current_route:
                    return True
        return False
