import logging
import datetime

logger = logging.getLogger(__name__)

def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_info(msg):
    logger.info("%23s %s" % (now(), msg))

def log_debug(msg):
    logger.debug("%22s %s" % (now(), msg))

def log_warn(msg):
    logger.warn("%20s %s" % (now(), msg))

def log_error(msg):
    logger.error("%22s %s" % (now(), msg))
