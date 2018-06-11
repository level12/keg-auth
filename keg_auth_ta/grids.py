import webgrid
from webgrid.flask import WebGrid as GridManager

from keg_auth_ta.model.entities import User


class Grid(webgrid.BaseGrid):
    manager = GridManager()
    session_on = True


class SampleGrid(Grid):
    webgrid.Column('Email', User.email)
