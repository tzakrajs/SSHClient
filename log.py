import logging

def new_logger(name, level):
    formatter = logging.Formatter(fmt='%(asctime)s - %(levelname)s - %(module)s - %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    if level is 'debug':
        logger.setLevel(logging.DEBUG)
    elif level is 'warning':
        logger.setLevel(logging.WARNING)
    elif level is 'info':
        logger.setLevel(logging.INFO)
    elif level is 'error':
        logger.setLevel(logging.ERROR)
    logger.addHandler(handler)
    return logger
