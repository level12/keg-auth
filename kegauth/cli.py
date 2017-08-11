from __future__ import print_function

import click

from kegauth.version import VERSION


@click.group()
@click.pass_context
def kegauth(ctx):
    pass


@kegauth.command()
def version():
    click.echo('version: {}'.format(VERSION))


@kegauth.command()
@click.argument('name', default='World')
def hello(name):
    click.echo('Hello {}!'.format(name))


def cli_entry():
    kegauth()
