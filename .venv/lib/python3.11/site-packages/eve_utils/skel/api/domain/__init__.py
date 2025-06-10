"""
Defines the resources that comprise the {$project_name} domain.
"""
from . import _settings


DOMAIN_DEFINITIONS = {
    '_settings': _settings.DEFINITION
}


DOMAIN_RELATIONS = {
}


DOMAIN = {**DOMAIN_DEFINITIONS, **DOMAIN_RELATIONS}
