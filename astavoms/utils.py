# Copyright 2016 GRNET S.A.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging


def setup_logger(given_logger, debug=False, logfile=None, use_console=None):
    """Create a stream logger and, optionally, a file logger
    :param given_logger: (str) the logger to setup
    :param debug: (bool) whether the logger will be set in INFO or DEBUG mode
    :param logfile: (str) path to the log file, will not log in file if None
    :param use_console: (bool) whether to print logs to console
    """
    given_logger.setLevel(logging.DEBUG)
    detailed_format = logging.Formatter(
        '%(asctime)s %(name)s:%(lineno)d %(levelname)s %(message)s')
    minimal_format = logging.Formatter('%(levelname)s: %(message)s')

    if logfile:
        file_handler = logging.FileHandler(logfile)
        file_handler.setLevel(logging.DEBUG if debug else logging.INFO)
        file_handler.setFormatter(detailed_format)
        given_logger.addHandler(file_handler)

    if use_console or not logfile:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG if debug else logging.ERROR)
        console_handler.setFormatter(minimal_format)
        given_logger.addHandler(console_handler)


def strip_dict(d):
    """:returns: (dict) a dict with all basestring values striped"""
    return dict(map(
        lambda (x, y): (x, y.strip() if isinstance(y, basestring) else y),
        d.items()))
