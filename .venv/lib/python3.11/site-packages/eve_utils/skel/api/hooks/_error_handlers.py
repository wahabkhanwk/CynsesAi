from pymongo.errors import ServerSelectionTimeoutError
from utils import make_error_response


def add_hooks(app):
    @app.errorhandler(Exception)
    def catchall_exception_handler(ex):
        return make_error_response('Unexpected server error', 500, exception=ex)

    @app.errorhandler(ServerSelectionTimeoutError)
    def mongo_missing_exception_handler(ex):
        message = 'Could not connect to mongodb.  ' \
                  'Ask server admin to check connection settings and ensure database is running.'
        return make_error_response(message, 500, exception=ex)
