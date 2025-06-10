import logging
import requests
from requests.exceptions import ConnectionError
import json
from configuration import SETTINGS

LOG = logging.getLogger('gateway')


def register(app):
    if not SETTINGS['ES_API_GATEWAY']:
        return

    if not SETTINGS['ES_BASE_URL']:
        LOG.warning('ES_API_GATEWAY is set, but cannot register because ES_BASE_URL is not set - cancelling')
        return

    url = f"{SETTINGS['ES_API_GATEWAY']}/registrations"  # TODO: use _links[registrations]
    name = SETTINGS['ES_API_NAME'] if not SETTINGS['ES_API_GATEWAY_NAME'] else SETTINGS['ES_API_GATEWAY_NAME']
    base_url = SETTINGS['ES_BASE_URL']
    LOG.info(f'Registering with gateway as {name} at {base_url} to {url}')
    api = app.test_client()
    response = api.get('/')
    j = response.json
    rels = j.get('_links', {})

    if rels:
        body = {
            'name': name,
            'baseUrl': base_url,
            'rels': rels
        }
        data = json.dumps(body)
        headers = {'content-type': 'application/json'}

        try:
            response = requests.get(url + '/' + name)
            if response.status_code == 404:
                response = requests.post(url, data=data, headers=headers)
            else:
                etag = response.json()['_etag']
                url = f"{SETTINGS['ES_API_GATEWAY']}/{response.json()['_links']['self']['href']}"
                headers = {
                    'content-type': 'application/json',
                    'If-Match': etag
                }
                print('=====>', data, '<====')
                response = requests.put(url, data=data, headers=headers)
        except ConnectionError:
            LOG.warning(f'Could not connect to API gateway at {url} - cancelling')
        # TODO: handle response
    else:
        LOG.warning('No rels to register - cancelling')
