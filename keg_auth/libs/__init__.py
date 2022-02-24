import flask
import flask_login


def get_current_user():
    """Helper to grab the authenticated user from the session.

    Trivial case is when the user is loaded in flask-login. If not, run the registered
    request loaders until we find a user.
    """
    # if flask_login has an authenticated user in session, that's who we want
    if flask_login.current_user and flask_login.current_user.is_authenticated:
        return flask_login.current_user

    # no user in session right now, so we need to run request loaders to see if any match
    user = None
    for loader in flask.current_app.auth_manager.request_loaders.values():
        user = loader.get_authenticated_user()
        if user:
            break
    if not user or not user.is_authenticated:
        return None
    return user


def get_domain_from_email(email):
    """Extract domain portion of email address."""
    parts = email.split('@')
    if len(parts) != 2:
        return None
    return parts[1]
