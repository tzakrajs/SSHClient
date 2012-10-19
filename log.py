# Copyright [2012] [Thomas Zakrajsek]
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging


def new_logger(name, level):
    formatter = logging.Formatter(fmt='%(asctime)s - %(levelname)s'
                                      ' - %(module)s - %(message)s')
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
