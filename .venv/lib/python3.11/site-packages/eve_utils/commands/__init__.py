import click

from . import api
from . import resource
from . import link
from . import integration
from . import affordance
from . import endpoint
from . import setting
from . import run

@click.group()
@click.version_option(package_name='eve-utils')
# @click.version_option()
def main():
    pass


def initialize():        
    main.add_command(api.commands)
    main.add_command(resource.commands)
    main.add_command(link.commands)
    main.add_command(integration.commands)
    main.add_command(affordance.commands)
    main.add_command(endpoint.commands)
    main.add_command(setting.commands)
    main.add_command(run.commands)
    main()
