import os
import click

@click.group(name='endpoint', help='Manage non-resource endpoints.')
def commands():
    pass

@commands.command(name='create', help='(not yet implemented)')
def create():
    click.echo(f'create')


@commands.command(name='list', help='(not yet implemented)')
def list():
    click.echo('list')


@commands.command(name='remove', help='(not yet implemented)')
def remove():
    click.echo('remove')
