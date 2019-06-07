import flask
import flask_login


def get_current_user():
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
