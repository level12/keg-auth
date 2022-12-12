import flask
import flask_login
import inflect
import keg.web
import sqlalchemy as sa
from blazeutils.strings import case_cw2dash
from keg.db import db
from flask_wtf.csrf import validate_csrf
from keg_auth import forms, grids, requires_permissions
from keg_auth.extensions import lazy_gettext as _, flash

try:
    from speaklater import is_lazy_string
except ImportError:
    is_lazy_string = lambda value: False  # noqa: E731


class CrudView(keg.web.BaseView):
    """Base CRUD view class providing add/edit/delete/list functionality.

    Basic subclass setup involves:
    - set the `grid_cls`, `form_cls`, and `orm_cls` attributes
    - set `object_name` to be the human readable label.
    - assign `object_name_plural` only if necessary
    - assign base permissions for reach of the four endpoints

    Grid is assumed to be WebGrid. Form is assumed to be WTForms. ORM is
    assumed to be SQLAlchemy. Default templates are provided with keg-auth.

    Permissions are set for each endpoint under the `permissions` dict attribute.
    Note that it is usually helpful to put a general @requires_permissions on the
    class itself, as that will aid in conditionally displaying navigation links
    based on a user's access level.
    """

    grid_cls = None
    form_cls = None
    orm_cls = None
    form_template = 'keg-auth/crud-addedit.html'
    grid_template = 'keg-auth/crud-list.html'
    object_name = None
    _inflect = inflect.engine()
    permissions = {
        'add': None,
        'edit': None,
        'delete': None,
        'list': None
    }

    @classmethod
    def map_method_route(cls, method_name, route, methods):
        method_route = keg.web.MethodRoute(method_name, route, {'methods': methods},
                                           cls.calc_url(use_blueprint=False),
                                           cls.calc_endpoint(use_blueprint=False))
        mr_options = method_route.options()
        view_func = cls.as_view(method_route.view_func_name,
                                method_route.sanitized_method_name('_'))
        cls.view_funcs[method_route.endpoint] = view_func
        mr_options['view_func'] = cls.view_funcs[method_route.endpoint]
        cls.blueprint.add_url_rule(method_route.rule(), **mr_options)

    @classmethod
    def init_routes(cls):
        """ Creates the standard set of routes from methods (add, edit, delete, list).

            To extend to further action routes:
                `cls.map_method_route(method_name, url, HTTP methods)`
                ex. `cls.map_method_route('read', '/foo', ('GET', ))`"""
        super(CrudView, cls).init_routes()

        cls.map_method_route('add', '{}/add'.format(cls.calc_url(use_blueprint=False)),
                             ('GET', 'POST'))
        cls.map_method_route(
            'edit',
            '{}/<int:objid>/edit'.format(cls.calc_url(use_blueprint=False)),
            ('GET', 'POST')
        )
        cls.map_method_route(
            'delete',
            '{}/<int:objid>/delete'.format(cls.calc_url(use_blueprint=False)),
            ('GET', )
        )
        cls.map_method_route('list', '{}'.format(cls.calc_url(use_blueprint=False)),
                             ('GET', 'POST'))

    def __init__(self, *args, **kwargs):
        super(CrudView, self).__init__(*args, **kwargs)
        self.objinst = None

    @property
    def object_name_plural(self):
        """Plural version of `object_name`. Uses the inflect library for a default value."""
        return self._inflect.plural(
            self.object_name
            if not is_lazy_string(self.object_name)
            else str(self.object_name)
        )

    def page_title(self, action):
        """Generates a heading title based on the page action.

        `action` should be a string. Values "Create" and "Edit" are handled, with a
        fall-through to return `object_name_plural` (for the list case).
        """
        if action == _('Create'):
            return _('Create {name}').format(name=self.object_name)

        if action == _('Edit'):
            return _('Edit {name}').format(name=self.object_name)

        return self.object_name_plural

    def create_form(self, obj):
        """Create an instance of `form_cls`. Must return a form if overloaded.

        `obj` is an instance of `orm_cls` (edit) or None (add).
        """
        return self.form_cls(obj=obj)

    def form_page_heading(self, action):
        """Allows customization of add/edit heading. Defaults to `page_title`."""
        return self.page_title(action)

    def form_template_args(self, arg_dict):
        """Allows customization of jinja template args for add/edit views.

        `arg_dict` contains the default arguments, including anything set with `self.assign`.

        Must return a dict of template args.
        """
        return arg_dict

    def render_form(self, obj, action, form, action_button_text=_('Save Changes')):
        """Renders the form template.

        Template arguments may be customized with the `form_template_args` method.
        """
        title_var = flask.current_app.config.get('KEGAUTH_TEMPLATE_TITLE_VAR')

        # args added with self.assign should be passed through here
        template_args = self.form_template_args(dict(self.template_args, **{
            'action': action,
            'action_button_text': action_button_text,
            'cancel_url': self.cancel_url(),
            'form': form,
            'obj_inst': obj,
            title_var: self.page_title(action),
            'page_heading': self.form_page_heading(action),
        }))
        return flask.render_template(self.form_template, **template_args)

    def add_orm_obj(self):
        """Generate a blank object instance and add it to the session."""
        o = self.orm_cls()
        db.session.add(o)
        return o

    def update_obj(self, obj, form):
        """Update an existing object instance from form data. Does not explicitly
        flush or commit."""
        obj = obj or self.add_orm_obj()
        form.populate_obj(obj)
        return obj

    def add_edit(self, meth, obj=None):
        """Handle form-related requests for add/edit.

        Form instance comes from `create_form`.
        Valid form updates the object via `update_obj`.
        If post successful, returns result of `on_add_edit_success`.
        If post failure, runs `on_add_edit_failure` and renders the form via `render_form`.
        If get, renders the form via `render_form`.
        """

        form = self.create_form(obj)
        if form is None:
            raise Exception('create_form returned None instead of a form instance')
        if meth == 'POST':
            if form.validate():
                result = self.update_obj(obj, form)
                db.session.commit()
                if result:
                    return self.on_add_edit_success(result, obj is not None)
            else:
                self.on_add_edit_failure(obj, obj is not None)

        return self.render_form(
            obj=obj,
            action=_('Edit') if obj else _('Create'),
            action_button_text=(
                _('Save Changes')
                if obj
                else _('Create {name}').format(name=self.object_name)
            ),
            form=form
        )

    def fetch_orm_obj(self, obj_id):
        return self.orm_cls.query.get(obj_id)

    def init_object(self, obj_id, action=None):
        """Load record from ORM for edit/delete cases.

        Forces 404 response if the record does not exist.

        Additional object-loading customization can be provided on action-specific hooks
        `init_object_edit` and `init_object_delete`. These methods will take no parameters, but
        they may assume `self.objinst` refers to the requested entity.
        """
        if obj_id is None:
            flask.abort(400)
        self.objinst = self.fetch_orm_obj(obj_id)
        if not self.objinst:
            flask.abort(404)
        if action:
            # Sometimes an action has particular requirements that are different from other actions.
            # For instance, a delete may be disallowed based on some property of the object itself,
            # which can't be trapped in permissions checks. Now that the object is loaded, see if
            # the view has an action init method.
            action_method = 'init_object_{}'.format(action)
            if hasattr(self, action_method):
                getattr(self, action_method)()
        return self.objinst

    def add(self):
        """View method for add. Enforce permissions and call `add_edit`."""
        return requires_permissions(self.permissions['add'])(self.add_edit)(flask.request.method)

    def edit(self, objid):
        """View method for edit. Enforce permissions, load the record, and call `add_edit`."""
        def action():
            obj = self.init_object(objid, 'edit')
            return self.add_edit(flask.request.method, obj)

        return requires_permissions(self.permissions['edit'])(action)()

    def delete(self, objid):
        """View method for delete. Enforce permissions, load the record, run ORM delete.

        If delete succeeds, return result of `on_delete_success`.
        If delete fails, return result of `on_delete_failure`.
        """
        def action():
            self.init_object(objid, 'delete')

            try:
                self.orm_cls.delete(objid)
            except sa.exc.IntegrityError:
                return self.on_delete_failure()

            return self.on_delete_success()

        return requires_permissions(self.permissions['delete'])(action)()

    def list(self):
        """View method for list. Enforce permissions, then render grid via `render_grid`."""
        return requires_permissions(self.permissions['list'])(self.render_grid)()

    @property
    def list_url_with_session(self):
        """Return list url with the session_key from the request, to support webgrid sessions."""
        return flask.url_for(self.endpoint_for_action('list'),
                             session_key=flask.request.args.get('session_key'))

    def flash_success(self, verb):
        """Add a flask flash message for success with the given `verb`."""
        # i18n: this may require reworking in order to support proper
        #       sentence structures...
        flash(_('Successfully {verb} {object}').format(
            verb=verb, object=self.object_name), 'success'
        )

    def on_delete_success(self):
        """Flash a delete success message, and redirect to list view."""
        self.flash_success(_('removed'))
        return flask.redirect(self.list_url_with_session)

    def on_delete_failure(self):
        """Flash a delete failure message, and redirect to list view."""
        flash(
            _('Unable to delete {name}. It may be referenced by other items.').format(
                name=self.object_name
            ),
            'warning'
        )
        return flask.redirect(self.list_url_with_session)

    def on_add_edit_success(self, entity, is_edit):
        """Flash an add/edit success message, and redirect to list view."""
        self.flash_success(
            _('modified')
            if is_edit
            else _('created')
        )
        return flask.redirect(self.list_url_with_session)

    def on_add_edit_failure(self, entity, is_edit):
        """Flash an add/edit message. No redirect in this case."""
        flash(_('Form errors detected.  Please see below for details.'), 'error')

    @classmethod
    def endpoint_for_action(cls, action):
        """Compute the flask endpoint for the given CRUD action."""
        return '{}:{}'.format(cls.calc_endpoint(), case_cw2dash(action))

    def make_grid(self):
        """Create an instance of `grid_cls` and initialize from request.

        Returns a grid instance."""
        grid = self.grid_cls()
        grid.apply_qs_args()
        return grid

    @property
    def grid_page_heading(self):
        """Allows customization of grid heading. Defaults to `page_title`."""
        return self.page_title(_('list'))

    def post_args_grid_setup(self, grid):
        """Apply changes to grid instance after QS args/session are loaded."""
        return grid

    def grid_template_args(self, arg_dict):
        """Allows customization of jinja template args for list view.

        `arg_dict` contains the default arguments, including anything set with `self.assign`.

        Must return a dict of template args.
        """
        return arg_dict

    def on_render_limit_exceeded(self, grid):
        """Flash a message for webgrid limit exceeded case.

        This gets run in export cases where more records are in the set than the
        file format can support."""
        flask.flash(_('Too many records to export as {}').format(grid.export_to), 'error')

    def render_grid(self):
        """Renders the grid template.

        Grid instance comes from `make_grid`.
        Grid instance may be customized via `post_args_grid_setup`.
        If grid is set to export, give that response or handle the limit exceeded error.
        Otherwise, render `grid_template` with `grid_template_args`.
        """
        grid = self.make_grid()
        grid = self.post_args_grid_setup(grid)

        if grid.session_on and flask.request.method.lower() == 'post':
            return flask.redirect(self.list_url_with_session)

        if grid.export_to:
            import webgrid

            try:
                return grid.export_as_response()
            except webgrid.renderers.RenderLimitExceeded:
                self.on_render_limit_exceeded(grid)

        title_var = flask.current_app.config.get('KEGAUTH_TEMPLATE_TITLE_VAR')

        # args added with self.assign should be passed through here
        template_args = self.grid_template_args(dict(self.template_args, **{
            'add_url': self.add_url_with_session(grid.session_key),
            title_var: self.page_title(_('list')),
            'page_heading': self.grid_page_heading,
            'object_name': self.object_name,
            'grid': grid,
        }))

        return flask.render_template(self.grid_template, **template_args)

    def add_url_with_session(self, session_key):
        """Return add url with the session_key from the request, to support webgrid sessions."""
        return flask.url_for(self.endpoint_for_action('add'), session_key=session_key)

    def cancel_url(self):
        """Return list url with the session_key from the request, to support webgrid sessions."""
        return self.list_url_with_session


class AuthRespondedView(keg.web.BaseView):
    """ Base for views which will refer out to the login authenticator for responders

        URL gets calculated from the responder class and must be a class attribute there.

        Note: if the login authenticator doesn't have the referenced key, the view will 404.
    """
    responder_key = None
    auth_manager = None
    auth_manager_key = 'login_authenticator'

    def __init__(self):
        super(AuthRespondedView, self).__init__()
        self.responding_method = 'responder'

    @classmethod
    def calc_url(cls, **kwargs):
        """Leans on login authenticator's responders to provide a URL."""
        authenticator_cls = getattr(cls.auth_manager, f'{cls.auth_manager_key}_cls')
        responder_cls = authenticator_cls.responder_cls.get(cls.responder_key)
        return getattr(responder_cls, 'url', None)

    def on_missing_responder(self):
        """Handler for requests that do not match a responder in authenticator.

        By default, aborts with 404 response."""
        flask.abort(404)

    def responder(self, *args, **kwargs):
        """Refer all requests to the responder and return the response.

        If no responder, call `on_missing_responder`."""
        authenticator = getattr(flask.current_app.auth_manager, self.auth_manager_key, None)
        if not authenticator:
            self.on_missing_responder()

        responder = authenticator.get_responder(self.responder_key)

        if not responder:
            self.on_missing_responder()

        return responder(*args, **kwargs)

    def get(self):
        # needed in keg to set up a GET route
        pass

    def post(self):
        # needed in keg to set up a POST route
        pass

    def head(self):
        # needed in keg to set up a HEAD route
        pass


class Login(AuthRespondedView):
    """Login view that uses the login authenticator's responders."""
    responder_key = 'login'


class OAuthLogin(AuthRespondedView):
    """Login view that uses the OAuth authenticator's responders."""
    responder_key = 'login'
    auth_manager_key = 'oauth_authenticator'

    @classmethod
    def calc_endpoint(cls, use_blueprint=True):
        prefix = (cls.blueprint.name + '.') if cls.blueprint and use_blueprint else ''
        return prefix + 'oauth-login'


class OAuthAuthorize(AuthRespondedView):
    """Authorization view that uses the OAuth authenticator's responders.

    Completes the OAuth login flow."""
    responder_key = 'authorize'
    auth_manager_key = 'oauth_authenticator'

    @classmethod
    def calc_endpoint(cls, use_blueprint=True):
        prefix = (cls.blueprint.name + '.') if cls.blueprint and use_blueprint else ''
        return prefix + 'oauth-authorize'


class ForgotPassword(AuthRespondedView):
    """Forgot Password view that uses the login authenticator's responders."""
    responder_key = 'forgot-password'


class ResetPassword(AuthRespondedView):
    """Reset Password view that uses the login authenticator's responders."""
    responder_key = 'reset-password'


class VerifyAccount(AuthRespondedView):
    """Verification view that uses the login authenticator's responders."""
    responder_key = 'verify-account'


class Logout(AuthRespondedView):
    """Logout view that uses the login authenticator's responders."""
    responder_key = 'logout'

    # Do this manually here, rather than using requires_user, because we want
    #   better control over what happens if an unauthenticated user uses the
    #   view. But, this prevents the route from being present in nav if a user
    #   is not logged in.
    __keg_auth_requires_user__ = True


@requires_permissions('auth-manage')
class User(CrudView):
    """Default User CRUD view. Uses auth-manage permission for all targets."""
    url = '/users'
    object_name = _('User')
    object_name_plural = _('Users')
    form_cls = staticmethod(forms.user_form)

    def create_form(self, obj):
        form_cls = self.form_cls(flask.current_app.config,
                                 allow_superuser=flask_login.current_user.is_superuser,
                                 endpoint=self.endpoint_for_action('edit'))
        return form_cls(obj=obj)

    @keg.web.route(post_only=True)
    def resend_verification_email(self):
        validate_csrf(flask.request.form['csrf_token'])
        auth_manager = keg.current_app.auth_manager
        if not auth_manager.login_authenticator.is_domain_excluded(flask.request.form['user_id']):
            auth_manager.resend_verification_email(flask.request.form['user_id'])
            flask.flash(str(_('Verification email has been sent')), 'success')
        return flask.redirect(flask.url_for(self.endpoint_for_action('list')))

    @property
    def orm_cls(self):
        return flask.current_app.auth_manager.entity_registry.user_cls

    @property
    def grid_cls(self):
        return grids.make_user_grid(
            edit_endpoint=self.endpoint_for_action('edit'),
            edit_permission=self.permissions['edit'],
            delete_endpoint=self.endpoint_for_action('delete'),
            delete_permission=self.permissions['delete'],
            resend_verification_endpoint=self.endpoint_for_action('resend-verification-email')
        )

    def create_user(self, form):
        auth_manager = keg.current_app.auth_manager
        email_enabled = (
            flask.current_app.config.get('KEGAUTH_EMAIL_OPS_ENABLED', True)
            and hasattr(form, 'send_welcome')
            and form.send_welcome.data
        )
        user_kwargs = {}
        user_kwargs['mail_enabled'] = email_enabled
        for field in form.data:
            # Only want fields that are on the class in kwargs
            # if we pass other stuff like permission_ids
            # user model wont be saved
            if hasattr(self.orm_cls, field):
                user_kwargs[field] = form[field].data
        user_kwargs['permissions'] = form.get_selected_permissions()
        user_kwargs['bundles'] = form.get_selected_bundles()
        user_kwargs['groups'] = form.get_selected_groups()
        obj = auth_manager.create_user(user_kwargs, _commit=False)
        return obj

    def update_obj(self, obj, form):
        if obj is None:
            obj = self.create_user(form)
        else:
            form.populate_obj(obj)
            obj.permissions = form.get_selected_permissions()
            obj.bundles = form.get_selected_bundles()
            obj.groups = form.get_selected_groups()
        # only reset a password if it is on the form and populated
        if hasattr(form, 'reset_password') and form.reset_password.data:
            obj.password = form.reset_password.data

        return obj

    def delete(self, objid):
        # ensure user cannot delete oneself
        if objid == flask_login.current_user.id:
            return self.on_delete_failure()
        return super(User, self).delete(objid)


@requires_permissions('auth-manage')
class Group(CrudView):
    """Default Group CRUD view. Uses auth-manage permission for all targets."""
    url = '/groups'
    object_name = _('Group')
    object_name_plural = _('Groups')
    form_cls = staticmethod(forms.group_form)

    def create_form(self, obj):
        form_cls = self.form_cls(endpoint=self.endpoint_for_action('edit'))
        return form_cls(obj=obj)

    @property
    def orm_cls(self):
        return flask.current_app.auth_manager.entity_registry.group_cls

    @property
    def grid_cls(self):
        return grids.make_group_grid(
            edit_endpoint=self.endpoint_for_action('edit'),
            edit_permission=self.permissions['edit'],
            delete_endpoint=self.endpoint_for_action('delete'),
            delete_permission=self.permissions['delete']
        )

    def update_obj(self, obj, form):
        obj = obj or self.add_orm_obj()
        form.populate_obj(obj)
        obj.permissions = form.get_selected_permissions()
        obj.bundles = form.get_selected_bundles()
        return obj


@requires_permissions('auth-manage')
class Bundle(CrudView):
    """Default Bundle CRUD view. Uses auth-manage permission for all targets."""
    url = '/bundles'
    object_name = _('Bundle')
    object_name_plural = _('Bundles')
    form_cls = staticmethod(forms.bundle_form)

    def create_form(self, obj):
        form_cls = self.form_cls(endpoint=self.endpoint_for_action('edit'))
        return form_cls(obj=obj)

    @property
    def orm_cls(self):
        return flask.current_app.auth_manager.entity_registry.bundle_cls

    @property
    def grid_cls(self):
        return grids.make_bundle_grid(
            edit_endpoint=self.endpoint_for_action('edit'),
            edit_permission=self.permissions['edit'],
            delete_endpoint=self.endpoint_for_action('delete'),
            delete_permission=self.permissions['delete']
        )

    def update_obj(self, obj, form):
        obj = obj or self.add_orm_obj()
        form.populate_obj(obj)
        obj.permissions = form.get_selected_permissions()
        return obj


@requires_permissions('auth-manage')
class Permission(keg.web.BaseView):
    """Default Permission view. Uses auth-manage permission."""
    url = '/permissions'
    grid_template = 'keg-auth/crud-list.html'

    @property
    def grid_cls(self):
        return grids.make_permission_grid()

    def get(self):
        grid = self.grid_cls()
        grid.apply_qs_args()

        if grid.export_to:
            return grid.export_as_response()

        title_var = flask.current_app.config.get('KEGAUTH_TEMPLATE_TITLE_VAR')
        self.assign(title_var, _('Permissions'))

        return flask.render_template(
            self.grid_template,
            page_heading=_('Permissions'),
            grid=grid,
            **self.template_args,
        )


def make_blueprint(import_name, _auth_manager, bp_name='auth', login_cls=Login,
                   forgot_cls=ForgotPassword, reset_cls=ResetPassword, logout_cls=Logout,
                   verify_cls=VerifyAccount, user_crud_cls=User, group_crud_cls=Group,
                   bundle_crud_cls=Bundle, permission_cls=Permission, oauth_login_cls=OAuthLogin,
                   oauth_auth_cls=OAuthAuthorize, blueprint_class=flask.Blueprint, **kwargs):
    """ Blueprint factory for keg-auth views

        Most params are assumed to be view classes. `_auth_manager` is the extension instance meant
        for the app on which this blueprint will be used: it is necessary in order to apply url
        routes for user functions.

        blueprint_class is the class to be instantiated as the Flask blueprint for auth views. The
        default is flask.blueprint, but a custom blueprint may be provided.
    """
    _blueprint = blueprint_class(bp_name, import_name, **kwargs)

    # auth responded views get the auth manager assigned for URL calculation, etc.
    # This has to happen before assign_blueprint.
    auth_responded_views = (
        login_cls, forgot_cls, reset_cls, verify_cls, logout_cls, oauth_login_cls, oauth_auth_cls
    )
    for view_cls in auth_responded_views:
        if view_cls:
            view_cls.auth_manager = _auth_manager

    for view_cls in (user_crud_cls, group_crud_cls, bundle_crud_cls, permission_cls,
                     *auth_responded_views):
        if view_cls:
            view_cls.assign_blueprint(_blueprint)

    return _blueprint
