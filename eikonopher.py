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
import string
from os import environ
import random
from datetime import datetime
import os
import os.path

import git
from flask import Flask, render_template, request, redirect, url_for, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.exceptions import BadRequest, InternalServerError, NotFound
from werkzeug.utils import secure_filename

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
    UPLOAD_PREFIX = environ.get('EIKONOPHER_UPLOAD_FOLDER')


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
    parser.add_argument('--upload-folder', default=Config.UPLOAD_PREFIX,
                        help='Path to a folder on the local filesystem in '
                             'which to put uploaded files.')

    parser.add_argument('--create-secret-key', action='store_true',
                        help='Generate a random string to use as a secret '
                             'key.')
    parser.add_argument('--create-db', action='store_true',
                        help="Create all DB objects.")

    args = parser.parse_args()

    Config.DEBUG = args.debug
    Config.PORT = args.port
    Config.SECRET_KEY = args.secret_key
    Config.DB_URI = args.db_uri
    Config.UPLOAD_FOLDER = args.upload_folder

app = Flask(__name__)

app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config["SECRET_KEY"] = Config.SECRET_KEY  # for WTF-forms and login
app.config['SQLALCHEMY_DATABASE_URI'] = Config.DB_URI

# extensions
db = SQLAlchemy(app)
app.db = db


class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), name='title')
    slug = db.Column(db.String(100), index=True, unique=True)
    description = db.Column(db.Text)
    filename = db.Column(db.Text)
    date = db.Column(db.DateTime)
    last_updated_date = db.Column(db.DateTime, nullable=False)

    def __init__(self, title, slug, description, filename, date,
                 last_updated_date):
        self.title = title
        self.slug = slug
        self.description = description
        self.filename = filename
        self.date = date
        self.last_updated_date = last_updated_date


class Options(object):
    @staticmethod
    def get_sitename():
        return 'eikonopher'

    @staticmethod
    def get_revision():
        return __revision__


def generate_slug(length=6, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in xrange(length))


@app.context_processor
def setup_options():
    return {'Options': Options}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/i/<slug>")
def get_image(slug):
    image = Image.query.filter_by(slug=slug).first()
    if not image:
        raise NotFound("No image found named \"{}\"".format(slug))
    return render_template('image.html', image=image)


@app.route("/raw/<slug>")
def get_raw_image(slug):
    image = Image.query.filter_by(slug=slug).first()
    if not image:
        raise NotFound("No image found named \"{}\"".format(slug))

    return send_file(image.filename)


@app.route("/new", methods=['GET', 'POST'])
def create_new():
    if request.method == 'GET':
        return render_template('new.html')

    title = request.form['title'].strip()
    if not title:
        raise BadRequest("The page's title is invalid.")

    f = request.files['file']
    sfilename = secure_filename(f.filename)
    filepart, ext = os.path.splitext(sfilename)

    slug_len = 6
    slug_count = 0
    while True:
        slug = generate_slug(slug_len)
        if not Image.query.filter_by(slug=slug).first():
            filename = slug + ext
            full_path = os.path.join(Config.UPLOAD_FOLDER, filename)
            if not os.path.exists(full_path):
                break
        slug_count += 1
        if slug_count > 6:
            slug_count = 0
            slug_len += 1
            if slug_len > 12:
                # TODO: get rid of this somehow. do it The Right Way, whatever
                # that is.
                raise InternalServerError('Can\'t find a unique filename')

    description = request.form['description']

    dt = datetime.utcnow()
    image = Image(title, slug, description, full_path, dt, dt)

    f.save(full_path)

    db.session.add(image)
    db.session.commit()
    return redirect(url_for('get_image', slug=image.slug))


def create_db():
    db.create_all()


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
    elif args.create_db:
        print('Setting up the database')
        create_db()
    else:
        app.run(debug=Config.DEBUG, port=Config.PORT,
                use_reloader=Config.DEBUG)
