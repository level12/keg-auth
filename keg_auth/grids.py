import flask
import flask_login
from markupsafe import Markup
import webgrid
from webgrid import filters

from keg_auth.extensions import lazy_gettext as _
from keg_auth.libs.templates import link_to, render_jinja
from keg_auth.model.utils import has_permissions
from flask_wtf.csrf import generate_csrf


class ActionColumn(webgrid.Column):
    """Places various action buttons in a Column.

    :param edit_permission_for: is a function that takes a row and returns the permission
                                required to open the edit endpoint for that row.
    :param delete_permission_for: is like `edit_permission_for`, but for the delete endpoint.
    :param view_permission_for: is like `edit_permission_for`, but for the view endpoint.
    :param view_link_class_for: is a function that takes a row and returns the HTML class to
                                place on the view link.
    :param edit_link_class_for: is a function that takes a row and returns the HTML class to
                                place on the edit link.
    :param delete_link_class_for: is a function that takes a row and returns the HTML class to
                                    place on the delete link.
    """
    default_view_link_class = 'view-link'
    default_edit_link_class = 'edit-link'
    default_delete_link_class = 'delete-link confirm-delete'

    def __init__(self,
                 label,
                 key=None,
                 filter=None,
                 can_sort=False,
                 render_in=('html',),
                 has_subtotal=False,
                 edit_endpoint=None,
                 delete_endpoint=None,
                 view_endpoint=None,
                 edit_permission_for=lambda row: None,
                 delete_permission_for=lambda row: None,
                 view_permission_for=lambda row: None,
                 view_link_class_for=None,
                 edit_link_class_for=None,
                 delete_link_class_for=None,
                 **kwargs):
        def link_class_for_fun(default_link_class):
            def link_class_for(row):
                return default_link_class

            return link_class_for

        if view_link_class_for is None:
            view_link_class_for = link_class_for_fun(self.default_view_link_class)
        if edit_link_class_for is None:
            edit_link_class_for = link_class_for_fun(self.default_edit_link_class)
        if delete_link_class_for is None:
            delete_link_class_for = link_class_for_fun(self.default_delete_link_class)

        self.edit_endpoint = edit_endpoint
        self.delete_endpoint = delete_endpoint
        self.view_endpoint = view_endpoint
        self.edit_permission_for = edit_permission_for
        self.delete_permission_for = delete_permission_for
        self.view_permission_for = view_permission_for
        self.view_link_class_for = view_link_class_for
        self.edit_link_class_for = edit_link_class_for
        self.delete_link_class_for = delete_link_class_for

        super(ActionColumn, self).__init__(label, key=key, filter=filter, can_sort=can_sort,
                                           render_in=render_in, has_subtotal=has_subtotal, **kwargs)

    def extract_and_format_data(self, record):
        view_perm = self.view_permission_for(record)
        edit_perm = self.edit_permission_for(record)
        delete_perm = self.delete_permission_for(record)
        can_edit = has_permissions(edit_perm, flask_login.current_user)
        can_delete = has_permissions(delete_perm, flask_login.current_user)
        can_view = (
            (self.edit_endpoint != self.view_endpoint or not can_edit)
            and has_permissions(view_perm, flask_login.current_user)
        )

        view_link_class = self.view_link_class_for(record)
        edit_link_class = self.edit_link_class_for(record)
        delete_link_class = self.delete_link_class_for(record)
        data = self.extract_data(record)
        return self.format_data(data, can_edit, can_delete, can_view,
                                view_link_class, edit_link_class, delete_link_class)

    def format_data(self, value, show_edit, show_delete, show_view,
                    view_link_class, edit_link_class, delete_link_class):
        result = Markup()
        if self.edit_endpoint and show_edit:
            result += link_to(
                Markup('&nbsp;'),
                flask.url_for(self.edit_endpoint, objid=value, session_key=self.grid.session_key),
                **{
                    'aria-label': _('Edit'),
                    'class': edit_link_class,
                    'title': _('Edit')
                }
            )
        if self.delete_endpoint and show_delete:
            result += link_to(
                Markup('&nbsp;'),
                flask.url_for(self.delete_endpoint, objid=value, session_key=self.grid.session_key),
                **{
                    'aria-label': _('Delete'),
                    'class': delete_link_class,
                    'title': _('Delete')
                }
            )
        if self.view_endpoint and show_view:
            result += link_to(
                Markup('&nbsp;'),
                flask.url_for(self.view_endpoint, objid=value, session_key=self.grid.session_key),
                **{
                    'aria-label': _('View'),
                    'class': view_link_class,
                    'title': _('View')
                }
            )
        return result


def make_user_grid(edit_endpoint, edit_permission, delete_endpoint, delete_permission,
                   grid_cls=None, resend_verification_endpoint=None):
    """Factory method to create a User grid class for CRUD."""
    user_cls = flask.current_app.auth_manager.entity_registry.user_cls
    grid_cls = grid_cls or flask.current_app.auth_manager.grid_cls
    action_column_cls = getattr(grid_cls, 'action_column_cls', ActionColumn)

    class ResendVerificationColumn(webgrid.Column):

        def __init__(self,
                     label,
                     url,
                     key=None,
                     render_in=('html',),
                     **kwargs):
            self.url = url
            super(ResendVerificationColumn, self).__init__(
                label, key=key, filter=None, can_sort=False,
                render_in=render_in, has_subtotal=False)

        def extract_and_format_data(self, record):
            return self.format_data(record)

        def format_data(self, data):
            result = Markup()
            if data.is_verified is False:
                result += render_jinja(
                    '<form action="{{ url }}" method="post">'
                    '<input type="hidden" name="csrf_token" value="{{ csrf_token }}" />'
                    '<input type="hidden" name="user_id" value="{{ user_id }}" />'
                    '<input type="submit" class"btn btn-primary" value="{{ submit_label }}" />'
                    '</form>',
                    url=flask.url_for(self.url),
                    csrf_token=generate_csrf(),
                    user_id=data.id,
                    submit_label=self.label,
                )
            return result

    class User(grid_cls):
        action_column_cls(
            '',
            user_cls.id,
            edit_endpoint=edit_endpoint,
            delete_endpoint=delete_endpoint,
            edit_permission_for=lambda _: edit_permission,
            delete_permission_for=lambda _: delete_permission
        )
        webgrid.Column(_('User ID'), user_cls.username, filters.TextFilter)
        if flask.current_app.auth_manager.mail_manager and hasattr(user_cls, 'is_verified'):
            webgrid.YesNoColumn(_('Verified'), user_cls.is_verified, filters.YesNoFilter)
        webgrid.YesNoColumn(_('Superuser'), user_cls.is_superuser, filters.YesNoFilter)
        if (
            flask.current_app.auth_manager.mail_manager
            and hasattr(user_cls, 'is_verified')
            and resend_verification_endpoint is not None
            and flask.current_app.config['KEGAUTH_EMAIL_OPS_ENABLED']
        ):
            ResendVerificationColumn(_('Resend Verification'), resend_verification_endpoint)

        def query_prep(self, query, has_sort, has_filters):
            if not has_sort:
                query = query.order_by(user_cls.username)
            return query
    return User


def make_group_grid(edit_endpoint, edit_permission, delete_endpoint, delete_permission,
                    grid_cls=None):
    """Factory method to create a Group grid class for CRUD."""
    group_cls = flask.current_app.auth_manager.entity_registry.group_cls
    grid_cls = grid_cls or flask.current_app.auth_manager.grid_cls
    action_column_cls = getattr(grid_cls, 'action_column_cls', ActionColumn)

    class Group(grid_cls):
        action_column_cls(
            '',
            group_cls.id,
            edit_endpoint=edit_endpoint,
            delete_endpoint=delete_endpoint,
            edit_permission_for=lambda _: edit_permission,
            delete_permission_for=lambda _: delete_permission
        )
        webgrid.Column(_('Name'), group_cls.name, filters.TextFilter)

        def query_prep(self, query, has_sort, has_filters):
            if not has_sort:
                query = query.order_by(group_cls.name)
            return query
    return Group


def make_bundle_grid(edit_endpoint, edit_permission, delete_endpoint, delete_permission,
                     grid_cls=None):
    """Factory method to create a Bundle grid class for CRUD."""
    bundle_cls = flask.current_app.auth_manager.entity_registry.bundle_cls
    grid_cls = grid_cls or flask.current_app.auth_manager.grid_cls
    action_column_cls = getattr(grid_cls, 'action_column_cls', ActionColumn)

    class Bundle(grid_cls):
        action_column_cls(
            '',
            bundle_cls.id,
            edit_endpoint=edit_endpoint,
            delete_endpoint=delete_endpoint,
            edit_permission_for=lambda _: edit_permission,
            delete_permission_for=lambda _: delete_permission
        )
        webgrid.Column(_('Name'), bundle_cls.name, filters.TextFilter)

        def query_prep(self, query, has_sort, has_filters):
            if not has_sort:
                query = query.order_by(bundle_cls.name)
            return query
    return Bundle


def make_permission_grid(grid_cls=None):
    """Factory method to create a Permission grid class."""
    permission_cls = flask.current_app.auth_manager.entity_registry.permission_cls
    grid_cls = grid_cls or flask.current_app.auth_manager.grid_cls

    class Permission(grid_cls):
        webgrid.Column(_('Name'), permission_cls.token, filters.TextFilter)
        webgrid.Column(_('Description'), permission_cls.description, filters.TextFilter)

        def query_prep(self, query, has_sort, has_filters):
            if not has_sort:
                query = query.order_by(permission_cls.token)
            return query
    return Permission
