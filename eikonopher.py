#!/usr/bin/env python

# eikonopher -  A simple python web service for hosting images and other files
# Copyright (C) 2016-2017 izrik
#
# This file is a part of eikonopher.
#
# Eikonopher is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Eikonopher is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with eikonopher.  If not, see <http://www.gnu.org/licenses/>.

import argparse
from os import environ

import git
from flask import Flask

try:
    __revision__ = git.Repo('.').git.describe(tags=True, dirty=True,
                                              always=True, abbrev=40)
except git.InvalidGitRepositoryError:
    __revision__ = 'unknown'


class Config(object):
    DEBUG = environ.get('EIKONOPHER_DEBUG', False)
    PORT = environ.get('EIKONOPHER_PORT', 4506)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('--debug', action='store_true',
                        help='Print additional information',
                        default=Config.DEBUG)
    parser.add_argument('--port', type=int, default=Config.PORT,
                        help='The tcp port on which to serve requests')

    args = parser.parse_args()

    Config.DEBUG = args.debug
    Config.PORT = args.port

app = Flask(__name__)

app.config['TEMPLATES_AUTO_RELOAD'] = True

if __name__ == "__main__":

    print('eikonopher')
    print('__revision__: {}'.format(__revision__))
    print('Debug: {}'.format(Config.DEBUG))
    print('Port: {}'.format(Config.PORT))

    app.run(debug=Config.DEBUG, port=Config.PORT, use_reloader=Config.DEBUG)
