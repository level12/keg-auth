import flask_login
import webgrid
from webgrid import filters
from webhelpers2.html import literal
from webhelpers2.html.tags import link_to

from keg_auth.model import entity_registry


class ActionColumn(webgrid.Column):
    """Places various action buttons in a Column.

    Since actions can be protected by permissions, this column must reside in a ProtectedGrid.
    """

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
                 delete_link_class_for=lambda row: 'delete-link confirm-delete',
                 **kwargs):
        """
        :param edit_permission_for: is a function that takes a row and returns the permission
                                    required to open the edit endpoint for that row.
        :param delete_permission_for: is like `edit_permission_for`, but for the delete endpoint.
        :param view_permission_for: is like `edit_permission_for`, but for the view endpoint.
        :param delete_link_class_for: is a function that takes a row and returns the HTML class to
                                      place on the delete link.
        """
        self.edit_endpoint = edit_endpoint
        self.delete_endpoint = delete_endpoint
        self.view_endpoint = view_endpoint
        self.edit_permission_for = edit_permission_for
        self.delete_permission_for = delete_permission_for
        self.view_permission_for = view_permission_for
        self.delete_link_class_for = delete_link_class_for

        super(ActionColumn, self).__init__(label, key=key, filter=filter, can_sort=can_sort,
                                           render_in=render_in, has_subtotal=has_subtotal, **kwargs)

    def extract_and_format_data(self, record):
        view_perm = self.view_permission_for(record)
        edit_perm = self.edit_permission_for(record)
        delete_perm = self.delete_permission_for(record)
        can_edit = flask_login.current_user.has_permissions(edit_perm)
        can_delete = flask_login.current_user.permissions(delete_perm)
        can_view = (
            (self.edit_endpoint != self.view_endpoint or not can_edit) and
            flask_login.current_user.permissions(view_perm)
        )

        delete_link_class = self.delete_link_class_for(record)
        data = self.extract_data(record)
        return self.format_data(data, can_edit, can_delete, can_view, delete_link_class)

    def format_data(self, value, show_edit, show_delete, show_view, delete_link_class):
        result = literal()
        if self.edit_endpoint and show_edit:
            result += link_to(
                literal('&nbsp;'),
                self.url_for(self.edit_endpoint, objid=value, session_key=self.grid.session_key),
                **{
                    'aria-label': 'Edit',
                    'class_': 'edit-link',
                    'title': 'Edit'
                }
            )
        if self.delete_endpoint and show_delete:
            result += link_to(
                literal('&nbsp;'),
                self.url_for(self.delete_endpoint, objid=value, session_key=self.grid.session_key),
                **{
                    'aria-label': 'Delete',
                    'class_': delete_link_class,
                    'title': 'Delete'
                }
            )
        if self.view_endpoint and show_view:
            result += link_to(
                literal('&nbsp;'),
                self.url_for(self.view_endpoint, objid=value, session_key=self.grid.session_key),
                **{
                    'aria-label': 'View',
                    'class_': 'view-link',
                    'title': 'View'
                }
            )
        return result

    def url_for(self, *args, **kwargs):
        """Proxies to the grid's `url_for` method."""
        try:
            return self.grid.url_for(*args, **kwargs)
        except AttributeError:  # pragma: no cover
            raise AttributeError('This column type must reside in an AppGrid')


def make_user_grid(edit_endpoint, edit_permission, delete_endpoint, delete_permission):
    user_cls = entity_registry.registry.user_cls

    class User(webgrid.BaseGrid):
        ActionColumn(
            '',
            user_cls.id,
            edit_endpoint=edit_endpoint,
            delete_endpoint=delete_endpoint,
            edit_permission_for=lambda _: edit_permission,
            delete_permission_for=lambda _: delete_permission
        )
        webgrid.Column('Email', user_cls.email, filters.TextFilter)
        webgrid.YesNoColumn('Verified', user_cls.is_verified, filters.YesNoFilter)
        webgrid.YesNoColumn('Superuser', user_cls.is_superuser, filters.YesNoFilter)

        def query_prep(self, query, has_sort, has_filters):
            if not has_sort:
                query = query.order_by(user_cls.email)
            return query
    return User


def make_group_grid(edit_endpoint, edit_permission, delete_endpoint, delete_permission):
    group_cls = entity_registry.registry.group_cls

    class Group(webgrid.BaseGrid):
        ActionColumn(
            '',
            group_cls.id,
            edit_endpoint=edit_endpoint,
            delete_endpoint=delete_endpoint,
            edit_permission_for=lambda _: edit_permission,
            delete_permission_for=lambda _: delete_permission
        )
        webgrid.Column('Name', group_cls.name, filters.TextFilter)

        def query_prep(self, query, has_sort, has_filters):
            if not has_sort:
                query = query.order_by(group_cls.name)
            return query
    return Group


def make_bundle_grid(edit_endpoint, edit_permission, delete_endpoint, delete_permission):
    bundle_cls = entity_registry.registry.bundle_cls

    class Bundle(webgrid.BaseGrid):
        ActionColumn(
            '',
            bundle_cls.id,
            edit_endpoint=edit_endpoint,
            delete_endpoint=delete_endpoint,
            edit_permission_for=lambda _: edit_permission,
            delete_permission_for=lambda _: delete_permission
        )
        webgrid.Column('Name', bundle_cls.name, filters.TextFilter)

        def query_prep(self, query, has_sort, has_filters):
            if not has_sort:
                query = query.order_by(bundle_cls.name)
            return query
    return Bundle
