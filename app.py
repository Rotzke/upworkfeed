#!/usr/bin/python3
"""Simple Flask-based Upwork API wrapper server."""
# import json
import os
from functools import wraps

from flask import (Flask, flash, redirect, render_template, request, session,
                   url_for)
from flask_pymongo import PyMongo
# from modules.betfair import get_data
from modules.forms import LoginForm
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['MONGO_DBNAME'] = 'upwork'
mongo = PyMongo(app)


def login_required(f):
    """Check if user is logged in."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You have to be logged in!', category='danger')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def validate(form):
    """Check user data in MongoDB."""
    user = mongo.db.users.find_one({'username': form.username.data})
    if user and check_password_hash(user['password'], form.password.data):
        return True
    else:
        return False


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login procedure function."""
    if 'username' in session:
        flash('You have to log out first!', category='warning')
        return redirect(url_for(request.referrer))
    form = LoginForm()
    if request.method == 'POST':
        if validate(form):
            flash('You have successfully logged in to the website!',
                  category='success')
            session['username'] = form.username.data
            return redirect(request.args.get('next') or url_for('index'))
        else:
            flash('Please check your login credentials!',
                  category='danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    """Log out from the website."""
    flash('Goodbye, {}!'.format(session['username']), category='success')
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/')
# @login_required
def index():
    """Show the main page."""
    return render_template('index.html', name='KOKOKO')


@app.route('/compare.json')
# @login_required
def compare():
    """Show the compare json."""
    return 'HELLO, WORLD!'  # json.dumps(get_data())


if __name__ == '__main__':
    app.run(debug=True)
