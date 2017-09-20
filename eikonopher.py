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
import random

import git
from flask import Flask, render_template

try:
    __revision__ = git.Repo('.').git.describe(tags=True, dirty=True,
                                              always=True, abbrev=40)
except git.InvalidGitRepositoryError:
    __revision__ = 'unknown'


class Config(object):
    DEBUG = environ.get('EIKONOPHER_DEBUG', False)
    PORT = environ.get('EIKONOPHER_PORT', 4506)
    SECRET_KEY = environ.get('EIKONOPHER_SECRET_KEY', 'secret')
    DB_URI = environ.get('EIKONOPHER_DB_URI', 'sqlite:////tmp/eikonopher.db')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('--debug', action='store_true',
                        help='Print additional information',
                        default=Config.DEBUG)
    parser.add_argument('--port', type=int, default=Config.PORT,
                        help='The tcp port on which to serve requests')
    parser.add_argument('--secret-key', type=str,
                        default=Config.SECRET_KEY,
                        help='The secret key used to establish secure '
                             'sessions with clients')
    parser.add_argument('--db-uri', default=Config.DB_URI,
                        help='The url at which to find the database.')

    parser.add_argument('--create-secret-key', action='store_true')

    args = parser.parse_args()

    Config.DEBUG = args.debug
    Config.PORT = args.port
    Config.SECRET_KEY = args.secret_key
    Config.DB_URI = args.db_uri

app = Flask(__name__)

app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config["SECRET_KEY"] = Config.SECRET_KEY  # for WTF-forms and login
app.config['SQLALCHEMY_DATABASE_URI'] = Config.DB_URI


class Options(object):
    @staticmethod
    def get_sitename():
        return 'eikonopher'

    @staticmethod
    def get_revision():
        return __revision__


@app.context_processor
def setup_options():
    return {'Options': Options}


@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":

    print('eikonopher')
    print('__revision__: {}'.format(__revision__))
    print('Debug: {}'.format(Config.DEBUG))
    print('Port: {}'.format(Config.PORT))
    if Config.DEBUG:
        print('Secret Key: {}'.format(Config.SECRET_KEY))
        print('DB URI: {}'.format(Config.DB_URI))

    if args.create_secret_key:
        digits = '0123456789abcdef'
        key = ''.join((random.choice(digits) for x in xrange(48)))
        print(key)
    else:
        app.run(debug=Config.DEBUG, port=Config.PORT,
                use_reloader=Config.DEBUG)
