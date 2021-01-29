import flask
from markupsafe import Markup


def render_jinja(source, **kwargs):
    template = flask.current_app.jinja_env.from_string(source)
    return Markup(template.render(**kwargs))


def link_to(label, url, **kwargs):
    return render_jinja(
        '<a href="{{url}}" {{- attrs|html_attributes }}>{{label}}</a>',
        url=url,
        attrs=kwargs,
        label=label
    )
