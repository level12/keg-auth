import webgrid

from keg_auth_ta.extensions import Grid
from keg_auth_ta.model.entities import User


class SampleGrid(Grid):
    webgrid.Column('Email', User.email)
