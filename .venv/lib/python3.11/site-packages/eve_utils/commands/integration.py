import os
import sys
import click
import eve_utils


@click.group(name='integration', help='Manage integrations with external services.')
def commands():
    pass


def _get_integrations():
    integrations_folder = os.path.join(os.path.dirname(eve_utils.__file__), 'skel/integration')
    integrations =  [name for name in os.listdir(integrations_folder) ]
    return integrations


@commands.command(name='create', short_help=f'Create an external integration to the service.')
@click.argument('integration', type=click.Choice(_get_integrations(), case_sensitive=False), metavar='<integration>')
@click.option('--name', '-n', help='Set or change the name of the integration.  If you do not supply a name, the name of the integration will be used (e.g. s3).  If you choose "empty" you must supply a name.', metavar='[name]')
@click.option('--prefix', '-p', help='Set the prefix used in settings this integration may require.', metavar='[prefix]')
def create(integration, name, prefix):
    """
    Create an external integration to the service.
    
    Integrations are used to keep separate the code you use to access other services, utilities, etc.
    
    Type 'eve-utils integration create' by itself to see a list of integrations available.
    """
    try:
        settings = eve_utils.jump_to_api_folder('src/{project_name}')
    except RuntimeError:
        print('This command must be run in an eve_service API folder structure')
        sys.exit(1)
        
    if integration == 'empty' and name is None:
        print('You must supply a name when choosing the "empty" integration.')
        sys.exit(902)

    if name is None:
        name = integration

    # TODO: ensure name is folder name friendly
    
    if os.path.exists(f'integration/{name}'):
        print(f'There already is an integration named "{name}".')
        sys.exit(901)

    print(f'creating {name} integration')

    if not os.path.exists('integration'):
        os.makedirs('integration')
    if not os.path.exists(f'integration/{name}'):
        os.makedirs(f'integration/{name}')

    replace = {
        'integration': name,
        'prefix': prefix.upper() if prefix else name.upper()
    }
    eve_utils.copy_skel(settings['project_name'], f'integration/{integration}', target_folder=f'integration/{name}', replace=replace)
    with open(f'./integration/__init__.py', 'a') as f:
        f.write(f'from . import {name}\n')
    # TODO: handle settings/prefix
    # TODO: ensure outer requirements.txt contains libraries required by the integration


@commands.command(name='list', help='(not yet implemented)')
def list():
    try:
        settings = eve_utils.jump_to_api_folder('src/{project_name}')
    except RuntimeError:
        print('This command must be run in an eve_service API folder structure')
        sys.exit(1)
        
    if not os.path.exists('integration'):
        print('No integrations have been added')
        sys.exit(0)
    
    integrations =  [name for name in os.listdir('./integration') ]
    for integration in integrations:
        if integration.startswith('_'):
            continue
        print(f'- {integration}')
    

@commands.command(name='remove', help='(not yet implemented)')
def remove():
    click.echo('remove')
