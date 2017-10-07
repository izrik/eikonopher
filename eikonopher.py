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
from flask_login import login_user, LoginManager, logout_user, current_user
from flask_wtf import FlaskForm, CSRFProtect
from werkzeug.exceptions import BadRequest, InternalServerError, NotFound
from werkzeug.utils import secure_filename
import bcrypt
from wtforms import StringField, PasswordField
from wtforms.validators import Email, DataRequired

try:
    __revision__ = git.Repo('.').git.describe(tags=True, dirty=True,
                                              always=True, abbrev=40)
except git.InvalidGitRepositoryError:
    __revision__ = 'unknown'


class Config(object):
    DEBUG = environ.get('EIKONOPHER_DEBUG', False)
    HOST = environ.get('EIKONOPHER_HOST', '127.0.0.1')
    PORT = environ.get('EIKONOPHER_PORT', 4506)
    SECRET_KEY = environ.get('EIKONOPHER_SECRET_KEY', 'secret')
    DB_URI = environ.get('EIKONOPHER_DB_URI', 'sqlite:////tmp/eikonopher.db')
    UPLOAD_PREFIX = environ.get('EIKONOPHER_UPLOAD_FOLDER')


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('--debug', action='store_true',
                        help='Print additional information',
                        default=Config.DEBUG)
    parser.add_argument('--host', type=str, default=Config.HOST,
                        help='The ip address to listen on. Set to 0.0.0.0 to '
                             'accept any incoming connections on any network '
                             'interface. Defaults to 127.0.0.1 for testing.')
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
    parser.add_argument('--hash-password', action='store',
                        help='Hash a password to be stored in the db.')
    parser.add_argument('--create-user', action='store', nargs=2,
                        metavar=('EMAIL', 'PASSWORD'),
                        help='Create a user in the DB.')

    args = parser.parse_args()

    Config.DEBUG = args.debug
    Config.HOST = args.host
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
login_manager = LoginManager()
login_manager.init_app(app)
csrf = CSRFProtect(app)


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


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100))
    hashed_password = db.Column(db.String(100))
    is_active = True
    is_authenticated = True
    is_active = True

    def __init__(self, email, hashed_password):
        self.email = email
        self.hashed_password = hashed_password

    def get_id(self):
        return unicode(self.email)


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
    return render_template("index.html", current_user=current_user)


@app.route("/i/<slug>")
def get_image(slug):
    image = Image.query.filter_by(slug=slug).first()
    if not image:
        raise NotFound("No image found named \"{}\"".format(slug))
    return render_template('image.html', image=image,
                           current_user=current_user)


@app.route("/raw/<slug>")
def get_raw_image(slug):
    image = Image.query.filter_by(slug=slug).first()
    if not image:
        raise NotFound("No image found named \"{}\"".format(slug))

    return send_file(image.filename)


@app.route("/new", methods=['GET', 'POST'])
def create_new():
    if request.method == 'GET':
        return render_template('new.html', current_user=current_user)

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


@login_manager.user_loader
def load_user(email):
    return User.query.filter_by(email=email).first()


class LoginForm(FlaskForm):
    email = StringField('email', validators=[Email(), DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'GET':
        return render_template('login.html', current_user=current_user,
                               form=form)

    if not form.validate_on_submit():
        return render_template('login.html', incorrect=True,
                               current_user=current_user, form=form)

    email = request.form['email']
    password = request.form['password']
    user = User.query.filter_by(email=email).first()
    if user is None:
        return render_template('login.html', incorrect=True,
                               current_user=current_user, form=form)

    if not bcrypt.checkpw(password.encode('utf-8'),
                          user.hashed_password.encode('utf-8')):
        return render_template('login.html', incorrect=True,
                               current_user=current_user, form=form)

    login_user(user)
    return redirect(request.args.get('next') or url_for('index'))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


def create_db():
    db.create_all()


if __name__ == "__main__":

    print('eikonopher')
    print('__revision__: {}'.format(__revision__))
    print('Debug: {}'.format(Config.DEBUG))
    print('Host: {}'.format(Config.HOST))
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
    elif args.hash_password is not None:
        password = args.hash_password
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
        print(hashed_password)
    elif args.create_user is not None:
        email, password = args.create_user
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
        print('Creating user "{}"'.format(email))
        user = User(email, hashed_password)
        db.session.add(user)
        db.session.commit()
    else:
        app.run(debug=Config.DEBUG, host=Config.HOST, port=Config.PORT,
                use_reloader=Config.DEBUG)
