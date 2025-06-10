import logging
from configuration import SETTINGS


LOG = logging.getLogger('{$integration}')

SETTINGS.set_prefix_description('{$prefix}', '--description--')
SETTINGS.create('{$prefix}', {
    'setting1': 'default_value',
    'setting2': 8080
})


# TODO: add methods here
