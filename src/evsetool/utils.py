import logging
import datetime

def logging_setup(logger_name, log_level=logging.ERROR, filename='evsetool.log'):
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)

    fh = logging.FileHandler('evsetool.log')
    fh.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(log_level)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)

    logger.addHandler(fh)
    logger.addHandler(ch)
    logger.info(f"Initialized console log handler at severity '{log_level}'")

    return logger

def rightnow():
    return datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
