"""Home of the auth modules that govern access via Eve."""
import os
import logging
import jwt
from configuration import SETTINGS

LOG = logging.getLogger('auth')

SETTINGS.set_prefix_description('ES-AUTH', 'EveService authorization settings')
SETTINGS.create('ES-AUTH', {
    'ADD_BASIC': 'No',  # [0] in 'yYtT', i.e. yes, Yes, true, True
    'ROOT_PASSWORD': 'password',
    'REALM': '{$project_name}.pointw.com',

    'JWT_DOMAIN': '{$project_name}.us.auth0.com',
    'JWT_ISSUER': 'https://{$project_name}.us.auth0.com/',
    'JWT_AUDIENCE': 'https://pointw.com/{$project_name}'
})

SETTINGS.set_prefix_description('AUTH0', 'Auth0 configuration')
SETTINGS.create('AUTH0', {
    'API_AUDIENCE': 'https://{$project_name}.us.auth0.com/api/v2/',
    'API_BASE_URL': 'https://{$project_name}.us.auth0.com/api/v2',
    'CLAIMS_NAMESPACE': 'https://pointw.com/{$project_name}',
    'TOKEN_ENDPOINT': 'https://{$project_name}.us.auth0.com/oauth/token',
    'CLIENT_ID': '--your-client-id--',
    'CLIENT_SECRET': '--your-client-secret--'
})

try:
    JWK_CLIENT = jwt.PyJWKClient(f'https://{SETTINGS["ES-AUTH_JWT_DOMAIN"]}/.well-known/jwks.json')
    _jwks = JWK_CLIENT.get_signing_keys()
    SIGNING_KEYS = {jwk.key_id: jwk.key for jwk in _jwks}
except jwt.exceptions.PyJWKClientError:
    LOG.warning('The auth addin is installed but not properly configured.')
    SIGNING_KEYS = {}

## # cancellable
## if SETTINGS['ES-AUTH_JWT_AUDIENCE'] == '':
##     del SETTINGS['ES-AUTH_JWT_AUDIENCE']
