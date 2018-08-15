import flask
import flask_login
import inflect
import keg.web
import sqlalchemy as sa
from blazeutils.strings import case_cw2dash
from keg.db import db
from six.moves import urllib

from keg_auth import forms, grids, requires_permissions
from keg_auth.libs import authenticators
from keg_auth.model import entity_registry


class _BaseView(keg.web.BaseView):

    def flash_and_redirect(self, flash_parts, auth_ident):
        flask.flash(*flash_parts)
        redirect_to = flask.current_app.auth_manager.url_for(auth_ident)
        flask.abort(flask.redirect(redirect_to))


class AuthFormView(_BaseView):
    flash_form_error = 'The form has errors, please see below.', 'error'
    flash_invalid_user = 'No user account matches: {}', 'error'
    flash_disabled_user = 'The user account "{}" has been disabled.  Please contact this' \
        ' site\'s administrators for more information.', 'error'

    def __init__(self, *args, **kwargs):
        super(AuthFormView, self).__init__(*args, **kwargs)

        self.authenticator = flask.current_app.auth_manager.primary_authenticator

    @property
    def form_action_text(self):
        return self.page_title

    @property
    def page_heading(self):
        return self.page_title

    def get(self):
        form = self.make_form()
        self.assign_template_vars(form)

    def post(self, user=None, token=None):
        form = self.make_form()
        if form.validate():
            kwargs = {}
            if user:
                kwargs['user'] = user
            if token:
                kwargs['token'] = token
            resp = self.on_form_valid(form, **kwargs)
            if resp is not None:
                return resp
        else:
            self.on_form_error(form)

        self.assign_template_vars(form)

    def assign_template_vars(self, form):
        self.assign('form', form)
        self.assign('form_action_text', self.form_action_text)
        self.assign('page_title', self.page_title)
        self.assign('page_heading', self.page_heading)

    @staticmethod
    def is_safe_url(target):
        """Returns `True` if the target is a valid URL for redirect"""
        # from http://flask.pocoo.org/snippets/62/
        ref_url = urllib.parse.urlparse(flask.request.host_url)
        test_url = urllib.parse.urlparse(urllib.parse.urljoin(flask.request.host_url, target))
        return (
            test_url.scheme in ('http', 'https') and
            ref_url.netloc == test_url.netloc
        )

    def make_form(self):
        return self.form_cls()

    def get_user(self, login_id=None, password=None):
        return self.authenticator.verify_user(login_id=login_id, password=password)

    def on_form_error(self, form):
        flask.flash(*self.flash_form_error)

    def on_invalid_user(self, form, field):
        message, category = self.flash_invalid_user
        val = getattr(form, field).data
        flask.flash(message.format(val), category)

    def on_disabled_user(self, user):
        message, category = self.flash_disabled_user
        flask.flash(message.format(user.display_value), category)


class CrudView(keg.web.BaseView):
    grid_cls = None
    form_cls = None
    orm_cls = None
    form_template = 'keg_auth/crud-addedit.html'
    grid_template = 'keg_auth/crud-list.html'
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
                                           cls.calc_url(), cls.calc_endpoint())
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

        cls.map_method_route('add', '{}/add'.format(cls.calc_url()), ('GET', 'POST'))
        cls.map_method_route('edit', '{}/<int:objid>/edit'.format(cls.calc_url()), ('GET', 'POST'))
        cls.map_method_route('delete', '{}/<int:objid>/delete'.format(cls.calc_url()), ('GET', ))
        cls.map_method_route('list', '{}'.format(cls.calc_url()), ('GET', 'POST'))

    def __init__(self, *args, **kwargs):
        super(CrudView, self).__init__(*args, **kwargs)
        self.objinst = None

    @property
    def object_name_plural(self):
        return self._inflect.plural(self.object_name)

    def page_title(self, action):
        if action in ('Create', 'Edit'):
            return '{} {}'.format(action, self.object_name)
        return self.object_name_plural

    def create_form(self, obj):
        return self.form_cls(obj=obj)

    def render_form(self, obj, action, form, action_button_text='Save Changes'):
        default_template_args = {
            'action': action,
            'action_button_text': action_button_text,
            'cancel_url': self.cancel_url(),
            'form': form,
            'obj_inst': obj,
            'page_title': self.page_title(action),
        }
        return flask.render_template(self.form_template, **default_template_args)

    def add_orm_obj(self):
        o = self.orm_cls()
        db.session.add(o)
        return o

    def update_obj(self, obj, form):
        obj = obj or self.add_orm_obj()
        form.populate_obj(obj)
        return obj

    def add_edit(self, meth, obj=None):
        form = self.create_form(obj)
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
            action='Edit' if obj else 'Create',
            action_button_text='Save Changes' if obj else 'Create ' + self.object_name,
            form=form
        )

    def init_object(self, obj_id):
        if obj_id is None:
            flask.abort(400)
        self.objinst = self.orm_cls.query.get(obj_id)
        if not self.objinst:
            flask.abort(404)
        return self.objinst

    def add(self):
        return requires_permissions(self.permissions['add'])(self.add_edit)(flask.request.method)

    def edit(self, objid):
        obj = self.init_object(objid)
        return requires_permissions(self.permissions['edit'])(self.add_edit)(
            flask.request.method, obj)

    def delete(self, objid):
        self.init_object(objid)

        def action():
            try:
                self.orm_cls.delete(objid)
            except sa.exc.IntegrityError:
                return self.on_delete_failure()

            return self.on_delete_success()

        return requires_permissions(self.permissions['delete'])(action)()

    def list(self):
        return requires_permissions(self.permissions['list'])(self.render_grid)()

    @property
    def list_url_with_session(self):
        return flask.url_for(self.endpoint_for_action('list'),
                             session_key=flask.request.args.get('session_key'))

    def flash_success(self, verb):
        flask.flash('Successfully {verb} {object}'.format(verb=verb, object=self.object_name),
                    'success')

    def on_delete_success(self):
        self.flash_success('removed')
        return flask.redirect(self.list_url_with_session)

    def on_delete_failure(self):
        flask.flash(
            'Unable to delete {}. It may be referenced by other items.'.format(self.object_name),
            'warning'
        )
        return flask.redirect(self.list_url_with_session)

    def on_add_edit_success(self, entity, is_edit):
        self.flash_success('modified' if is_edit else 'created')
        return flask.redirect(self.list_url_with_session)

    def on_add_edit_failure(self, entity, is_edit):
        flask.flash('Form errors detected.  Please see below for details.', 'error')

    @classmethod
    def endpoint_for_action(cls, action):
        return '{}.{}:{}'.format(cls.blueprint.name, cls.calc_endpoint(), case_cw2dash(action))

    def make_grid(self):
        grid = self.grid_cls()
        grid.apply_qs_args()
        return grid

    def render_grid(self):
        grid = self.make_grid()

        if grid.export_to:
            return grid.export_as_response()

        return flask.render_template(
            self.grid_template,
            add_url=flask.url_for(self.endpoint_for_action('add'),
                                  session_key=grid.session_key),
            page_title=self.page_title('list'),
            grid=grid
        )

    def cancel_url(self):
        return self.list_url_with_session


class Login(AuthFormView):
    url = '/login'
    template_name = 'keg_auth/login.html'
    page_title = 'Log In'
    flash_success = 'Login successful.', 'success'
    flash_invalid_password = 'Invalid password.', 'error'
    flash_unverified_user = 'The user account "{}" has an unverified email address.  Please check' \
        ' your email for a verification link from this website.  Or, use the "forgot' \
        ' password" link to verify the account.', 'error'

    @property
    def form_cls(self):
        return forms.login_form()

    def on_form_valid(self, form):
        try:
            user = self.get_user(login_id=form.login_id.data, password=form.password.data)

            # User is active and password is verified
            return self.on_success(user)
        except authenticators.UserNotFound:
            self.on_invalid_user(form, 'login_id')
        except authenticators.UserInactive as exc:
            self.on_inactive_user(exc.user)
        except authenticators.UserInvalidAuth:
            self.on_invalid_password()

    def on_invalid_password(self):
        flask.flash(*self.flash_invalid_password)

    def on_inactive_user(self, user):
        if flask.current_app.auth_manager.mail_manager and not user.is_verified:
            message, category = self.flash_unverified_user
            flask.flash(message.format(user.email), category)
        if not user.is_enabled:
            self.on_disabled_user(user)

    def on_success(self, user):
        flask_login.login_user(user)
        flask.flash(*self.flash_success)

        # support Flask-Login "next" parameter
        next_parameter = flask.request.values.get('next')
        if flask.current_app.config.get('USE_SESSION_FOR_NEXT'):
            next_parameter = flask.session.get('next')
        if next_parameter and self.is_safe_url(next_parameter):
            redirect_to = next_parameter
        else:
            redirect_to = flask.current_app.auth_manager.url_for('after-login')

        return flask.redirect(redirect_to)


class ForgotPassword(AuthFormView):
    url = '/forgot-password'
    form_cls = forms.ForgotPassword
    page_title = 'Initiate Password Reset'
    template_name = 'keg_auth/forgot-password.html'
    flash_success = 'Please check your email for the link to change your password.', 'success'

    def check_auth(self):
        if not flask.current_app.auth_manager.mail_manager:
            flask.abort(404)

    def on_form_valid(self, form):
        try:
            user = self.get_user(login_id=form.email.data)

            # User is active, take action to initiate password reset
            return self.on_success(user)
        except authenticators.UserNotFound:
            self.on_invalid_user(form, 'email')
        except authenticators.UserInactive as exc:
            self.on_disabled_user(exc.user)

    def on_success(self, user):
        self.send_email(user)
        flask.flash(*self.flash_success)
        redirect_to = flask.current_app.auth_manager.url_for('after-forgot')
        return flask.redirect(redirect_to)

    def send_email(self, user):
        user.token_generate()
        flask.current_app.auth_manager.mail_manager.send_reset_password(user)


class SetPasswordBaseView(AuthFormView):
    form_cls = forms.SetPassword
    template_name = 'keg_auth/set-password.html'
    flash_invalid_token = 'Authentication token was invalid or expired.  Please fill out the' \
        ' form below to get a new token.', 'error'

    def check_auth(self):
        if not flask.current_app.auth_manager.mail_manager:
            flask.abort(404)

    def user_loader(self, user_id):
        user_ent = flask.current_app.auth_manager.entity_registry.user_cls
        return user_ent.query.get(user_id)

    def pre_method(self, user, token):
        if not user.token_verify(token):
            resp = self.on_invalid_token()
            # In case on_invalid_token() is replaced and it accidently fails to return a value
            # make sure we change that to a generic 400.
            flask.abort(resp or 400)

    def on_form_valid(self, form, user=None, token=None):
        assert user is not None
        assert token is not None
        return self.on_success(form, user, token)

    def on_success(self, form, user, token):
        new_password = form.password.data
        user.change_password(token, new_password)
        self.flash_and_redirect(self.flash_success, self.on_success_endpoint)

    def on_invalid_token(self):
        self.flash_and_redirect(self.flash_invalid_token, 'forgot-password')

    def assign_template_vars(self, form):
        super(SetPasswordBaseView, self).assign_template_vars(form)
        self.assign('submit_button_text', self.submit_button_text)


class ResetPassword(SetPasswordBaseView):
    url = '/reset-password/<int:user_id>/<token>'
    page_title = 'Complete Password Reset'
    submit_button_text = 'Change Password'
    flash_success = 'Password changed.  Please use the new password to login below.', 'success'
    on_success_endpoint = 'after-reset'


class VerifyAccount(SetPasswordBaseView):
    url = '/verify-account/<int:user_id>/<token>'
    page_title = 'Verify Account & Set Password'
    submit_button_text = 'Verify & Set Password'
    flash_success = 'Account verified & password set.  Please use the new password to login' \
        ' below.', 'success'
    on_success_endpoint = 'after-verify-account'


class Logout(_BaseView):
    url = '/logout'
    flash_success = 'You have been logged out.', 'success'

    def get(self):
        flask_login.logout_user()
        self.flash_and_redirect(self.flash_success, 'after-logout')


@requires_permissions('auth-manage')
class User(CrudView):
    url = '/users'
    object_name = 'User'
    form_cls = staticmethod(forms.user_form)

    def create_form(self, obj):
        form_cls = self.form_cls(flask.current_app.config,
                                 allow_superuser=flask_login.current_user.is_superuser,
                                 endpoint=self.endpoint_for_action('edit'))
        return form_cls(obj=obj)

    @property
    def orm_cls(self):
        return flask.current_app.auth_manager.entity_registry.user_cls

    @property
    def grid_cls(self):
        return grids.make_user_grid(
            edit_endpoint=self.endpoint_for_action('edit'),
            edit_permission=self.permissions['edit'],
            delete_endpoint=self.endpoint_for_action('delete'),
            delete_permission=self.permissions['delete']
        )

    def update_obj(self, obj, form):
        obj = obj or self.add_orm_obj()
        form.populate_obj(obj)

        # only reset a password if it is on the form and populated
        if hasattr(form, 'reset_password') and form.reset_password.data:
            obj.password = form.reset_password.data

        obj.permissions = form.get_selected_permissions()
        obj.bundles = form.get_selected_bundles()
        obj.groups = form.get_selected_groups()
        return obj

    def delete(self, objid):
        # ensure user cannot delete oneself
        if objid == flask_login.current_user.id:
            return self.on_delete_failure()
        return super(User, self).delete(objid)


@requires_permissions('auth-manage')
class Group(CrudView):
    url = '/groups'
    object_name = 'Group'
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
    url = '/bundles'
    object_name = 'Bundle'
    form_cls = staticmethod(forms.bundle_form)

    def create_form(self, obj):
        form_cls = self.form_cls(endpoint=self.endpoint_for_action('edit'))
        return form_cls(obj=obj)

    @property
    def orm_cls(self):
        return flask.current_app.auth_manager.entity_registry.bundle_cls

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
        return obj


@requires_permissions('auth-manage')
class Permission(keg.web.BaseView):
    url = '/permissions'
    grid_template = 'keg_auth/crud-list.html'

    @property
    def grid_cls(self):
        return grids.make_permission_grid()

    def get(self):
        grid = self.grid_cls()
        grid.apply_qs_args()

        if grid.export_to:
            return grid.export_as_response()

        return flask.render_template(
            self.grid_template,
            page_title='Permissions',
            grid=grid
        )


def make_blueprint(import_name, bp_name='auth', login_cls=Login, forgot_cls=ForgotPassword,
                   reset_cls=ResetPassword, logout_cls=Logout, verify_cls=VerifyAccount,
                   user_crud_cls=User, group_crud_cls=Group, bundle_crud_cls=Bundle,
                   permission_cls=Permission):

    _blueprint = flask.Blueprint(bp_name, import_name)

    # It's not ideal we have to redefine the classes, but it's needed because of how
    # Keg.web.BaseView does it's meta programming.  If we don't redefine the class, then
    # the view doesn't actually get created on blueprint.
    class Login(login_cls):
        blueprint = _blueprint

    class ForgotPassword(forgot_cls):
        blueprint = _blueprint

    class ResetPassword(reset_cls):
        blueprint = _blueprint

    class Logout(logout_cls):
        blueprint = _blueprint

    class VerifyAccount(verify_cls):
        blueprint = _blueprint

    class User(user_crud_cls):
        blueprint = _blueprint

    class Group(group_crud_cls):
        blueprint = _blueprint

    class Bundle(bundle_crud_cls):
        blueprint = _blueprint

    class Permission(permission_cls):
        blueprint = _blueprint

    return _blueprint
