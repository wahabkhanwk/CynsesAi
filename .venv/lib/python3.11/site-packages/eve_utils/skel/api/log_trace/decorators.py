"""
Function decorators used in this project
- @trace - log_trace entries and exits of decorated function
"""
import logging
from functools import wraps
from typing import Any, Callable
from configuration import SETTINGS

LOG = logging.getLogger('trace')


def _trace(target):
    """
    This is a decorator that log_trace when the decorated function is entered and exited.
    Any unhandled exceptions raised by the decorated function are logged and re-raised.
    """

    @wraps(target)
    def _wrapper(*args, **kwargs):
        return_value = None
        LOG.trace(f'Entering function: {target.__module__}.{target.__name__}')

        try:
            return_value = target(*args, **kwargs)
        except Exception as ex:  # pylint: disable=broad-except
            LOG.trace(f'Exiting function: {target.__module__}.{target.__name__} by unhandled exception "{ex}"')
            LOG.exception(ex)
            raise

        LOG.trace(f'Exiting function: [{target.__module__}].[{target.__name__}] by return')

        return return_value

    return _wrapper


if SETTINGS.is_enabled('ES_TRACE_LOGGING'):
    trace = _trace
else:
    trace: Callable[[Any], Any] = lambda fn: fn
