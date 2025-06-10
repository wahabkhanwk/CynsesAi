import os
import sys
import click
import eve_utils
import platform

@click.command(name='run', help='Launch the service.')
def commands():
    try:
        settings = eve_utils.jump_to_api_folder('src/{project_name}')
    except RuntimeError:
        print('This command must be run in an eve_service API folder structure')
        sys.exit(1)
        
    try:
        import eve
        import cerberus
    except ModuleNotFoundError:
        # TODO: ask first?
        os.system('pip install -r requirements.txt')
        
    cmd = 'python run.py'    
    if platform.system() == 'Windows':
        cmd = f"start \"{settings['project_name']}\" python run.py"

    os.system(cmd)
