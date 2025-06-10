"""Defines TRACE logging verbosity"""
import logging

TRACE_LEVEL = 5
TRACE_NAME = 'TRACE'
TRACE_METHOD = 'trace'


def add_logging_level(level_name, level_number, method_name=None):
    """
    Copied/modified from https://stackoverflow.com/a/35804945/1155004
    Comprehensively adds a new logging level to the `logging` module and the
    currently configured logging class.

    `levelName` becomes an attribute of the `logging` module with the value
    `levelNum`. `methodName` becomes a convenience method for both `logging`
    itself and the class returned by `logging.getLoggerClass()` (usually just
    `logging.Logger`). If `methodName` is not specified, `levelName.lower()` is
    used.

    To avoid accidental clobberings of existing attributes, this method will
    raise an `AttributeError` if the level name is already an attribute of the
    `logging` module or if the method name is already present

    Example
    -------
    >>> addLoggingLevel('TRACE', logging.DEBUG - 5)
    >>> logging.getLogger(__name__).setLevel("TRACE")
    >>> logging.getLogger(__name__).trace('that worked')
    >>> logging.trace('so did this')
    >>> logging.TRACE
    5

    """
    if not method_name:
        method_name = level_name.lower()

    if hasattr(logging, level_name):
        raise AttributeError('{} already defined in logging module'.format(level_name))
    if hasattr(logging, method_name):
        raise AttributeError('{} already defined in logging module'.format(method_name))
    if hasattr(logging.getLoggerClass(), method_name):
        raise AttributeError('{} already defined in logger class'.format(method_name))

    # This method was inspired by the answers to Stack Overflow post
    # http://stackoverflow.com/q/2183233/2988730, especially
    # http://stackoverflow.com/a/13638084/2988730
    def log_for_level(self, message, *args, **kwargs):
        if self.isEnabledFor(level_number):
            self._log(level_number, message, args, **kwargs)

    def log_to_root(message, *args, **kwargs):
        logging.log(level_number, message, *args, **kwargs)

    logging.addLevelName(level_number, level_name)
    setattr(logging, level_name, level_number)
    setattr(logging.getLoggerClass(), method_name, log_for_level)
    setattr(logging, method_name, log_to_root)


add_logging_level(TRACE_NAME, TRACE_LEVEL, TRACE_METHOD)


# logging.addLevelName(TRACE_LEVEL, TRACE_NAME)
#
#
# def trace(self, message, *args, **kws):
#     """Extends logging with TRACE level"""
#     if self.isEnabledFor(TRACE_LEVEL):
#         self._log(TRACE_LEVEL, message, args, **kws)  # pylint: disable=protected-access
#
#
# def log_to_root(message, *args, **kwargs):
#     logging.log(TRACE_LEVEL, message, *args, **kwargs)
#
#
# # logging.Logger.trace = trace
# setattr(logging, TRACE_NAME, TRACE_LEVEL)
# setattr(logging.getLoggerClass(), TRACE_METHOD, trace)
# setattr(logging, TRACE_METHOD, log_to_root)
