import os
import signal
from eve_service import EveService


def stop_api(signum, frame):  # pylint: disable=unused-argument
    """ Catches SIGTERM and issues SIGINT """
    if signum == signal.SIGTERM:
        os.kill(os.getpid(), signal.SIGINT)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, stop_api)

    eve = EveService()

    try:
        eve.start()
    except KeyboardInterrupt:
        eve.stop()
