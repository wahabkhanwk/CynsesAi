import os
import socket

from . import settings

VERSION = '0.1.0'


# set environment variables from _env.conf (which is in .gitignore)
if os.path.exists('_env.conf'):
    with open('_env.conf') as setting:
        for line in setting:
            if not line.startswith('#'):
                line = line.rstrip()
                nvp = line.split('=')
                if len(nvp) == 2:
                    os.environ[nvp[0].strip()] = nvp[1].strip()


SETTINGS = settings.Settings.instance()
SETTINGS.set_prefix_description('ES', 'EveService base configuration')
SETTINGS.create('ES', {
    'API_NAME': '{$project_name}',

    'MONGO_ATLAS': 'Disabled',
    'MONGO_HOST': 'localhost',
    'MONGO_PORT': 27017,
    'MONGO_DBNAME': '{$project_name}',
    'API_PORT': 2112,
    'INSTANCE_NAME': socket.gethostname(),
    'TRACE_LOGGING': 'Enabled',
    'PAGINATION_LIMIT': 3000,
    'PAGINATION_DEFAULT': 1000,
    'ADD_ECHO': 'Disabled',
    'LOG_TO_FOLDER': 'Disabled',
    'SEND_ERROR_EMAILS': 'Disabled',
})

# optional settings...
SETTINGS.create('ES', 'BASE_URL', is_optional=True)
SETTINGS.create('ES', 'API_GATEWAY', is_optional=True)
SETTINGS.create('ES', 'API_GATEWAY_NAME', is_optional=True)
SETTINGS.create('ES', 'URL_PREFIX', is_optional=True)
SETTINGS.create('ES', 'CACHE_CONTROL', is_optional=True)
SETTINGS.create('ES', 'CACHE_EXPIRES', is_optional=True, default_value=0)
SETTINGS.create('ES', 'MONGO_USERNAME', is_optional=True)
SETTINGS.create('ES', 'MONGO_PASSWORD', is_optional=True)
SETTINGS.create('ES', 'MONGO_AUTH_SOURCE', is_optional=True)
SETTINGS.create('ES', 'MEDIA_BASE_URL', is_optional=True)
SETTINGS.create('ES', 'PUBLIC_RESOURCES', is_optional=True)

if SETTINGS.is_enabled('ES_SEND_ERROR_EMAILS'):
    SETTINGS.create('ES', 'SMTP_PORT', default_value=25)
    SETTINGS.create('ES', 'SMTP_HOST', is_optional=True)
    SETTINGS.create('ES', 'ERROR_EMAIL_RECIPIENTS', is_optional=True)
    SETTINGS.create('ES', 'ERROR_EMAIL_FROM', is_optional=True)

# cancellable settings...
# if SETTINGS.get('ES_CANCELLABLE') == '':
#     del SETTINGS['ES_CANCELLABLE']
