import jwt
from base64 import b64decode
from auth import SETTINGS, SIGNING_KEYS


def basic(token, **kwargs):
    try:
        username, password = b64decode(token).decode().split(':', 1)
        is_root = False
        if username.lower() == 'root':
            if password == SETTINGS.get('ES-AUTH_ROOT_PASSWORD'):
                is_root = True
            else:
                return {}

        role = 'admin' if is_root else ''
        rtn = {
            'user': username,
            'role': role
        }
    except:
        rtn = {}

    return rtn


# TODO: detect opaque token, then handle accordingly (how?)
def bearer(token, **kwargs):
    audience = SETTINGS.get('ES-AUTH_JWT_AUDIENCE')
    issuer = SETTINGS.get('ES-AUTH_JWT_ISSUER')

    options = {}

    if audience:
        options['audience'] = audience
    if issuer:
        options['issuer'] = issuer

    try:
        headers = jwt.get_unverified_header(token)
        options['algorithms'] = [headers['alg']]
        signing_key = SIGNING_KEYS[headers['kid']]  # TODO: this will fail if SETTINGS not properly configured - except key error? test then raise?

        parsed = jwt.decode(token, signing_key, **options)
        rtn = {
            'user': parsed.get('sub')
        }

        claims_namespace = SETTINGS['AUTH0_CLAIMS_NAMESPACE']
        claims = parsed.get(f'{claims_namespace}/claims')
        rtn['permissions'] = parsed.get('permissions', [])

        for claim in ['id', 'name', 'nickname', 'email', 'roles']:
            value = claims.get(claim)
            if value:
                rtn[claim] = value
        if 'roles' in rtn:
            rtn['roles'] = [role.lower() for role in rtn['roles']]
            if 'admin' in rtn['roles']:
                rtn['role'] = 'admin'

    except (jwt.ExpiredSignatureError,
            jwt.InvalidSignatureError,
            jwt.InvalidAudienceError,
            jwt.InvalidAlgorithmError) as ex:  # TODO: other jwt ex's?
        rtn = {'_issues': {'token': f'{ex}'}}
    except ValueError as ex:
        rtn = {'_issues': {'config': f'{ex} - Please contact support for assistance, quoting this message'}}
    except jwt.DecodeError as ex:
        # NOTE: this should never occur - only did during development of this handler
        rtn = {'_issues': {'auth_handler': f'{ex} - Please contact support for assistance, quoting this message'}}
    except Exception as ex:
        rtn = {'_issues': {'unknown': f'{ex} - Please contact support for assistance, quoting this message'}}

    return rtn


def bearer_challenge(**kwargs):
    request = kwargs.get('request')
    rtn = {}
    if request and (
        'Bearer' in request.headers.get('Authorization', '')
        or request.args.get('access_token')
    ):
        rtn['error'] = "invalid_token"

    return rtn
