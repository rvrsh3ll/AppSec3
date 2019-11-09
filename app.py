
from flask import Flask, request, render_template, redirect, url_for, request, session, flash, g
from flask_api import status
from functools import wraps
from flask_wtf.csrf import CSRFProtect
import subprocess
import os
from passlib.hash import sha256_crypt, pbkdf2_sha256
#from flask_talisman import Talisman
from flask_sqlalchemy import SQLAlchemy
#from flask_sqlalchemy.exc import IntegrityError
from datetime import datetime



app = Flask(__name__)
#talisman = Talisman(app, force_https=False)

app.config.from_object('config.DefaultConfig')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///spell.db'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    twofa = db.Column(db.String(), nullable=True)
    password = db.Column(db.String(60), nullable=False)
    isadmin = db.Column(db.Boolean(), nullable=False, default=False)
    queries = db.relationship('Query', backref='bruser', lazy=True)
    logs = db.relationship('Logs', backref='bruser', lazy=True)

#    def __repr__(self):
#       return f"User('{self.username}', '{self.twofa}', '{self.password}')"

class Query(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    submission = db.Column(db.String(), nullable=False)
    results = db.Column(db.String(), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Query('{self.id}, {self.submission}, {self.results}')"

class Logs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    logout = db.Column(db.DateTime, nullable=True, default=None)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Logs('{self.login}', '{self.logout}')"

db.create_all()
Users = {}

if (db.session.query(User.id).filter_by(username='admin').scalar() is None):
    admin = User(username='admin', password=pbkdf2_sha256.hash('Administrator@1'), twofa='12345678901', isadmin=True)
    db.session.add(admin)
    db.session.commit()

#def checkUser(dict, key):
#    if key in dict.keys():
#        return True
#    else:
#        return False

#create new decorator to require login
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            errorMess = 'You need to login first.'
            return errorMess, status.HTTP_401_UNAUTHORIZED
    wrap.__name__ = f.__name__
    return wrap

def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'user' in session:
            currentuser = User.query.filter_by(username=session['user']).first()
            if currentuser.isadmin:
                return f(*args, **kwargs)
        else:
            errorMess = 'Admin login required.'
            return errorMess, status.HTTP_401_UNAUTHORIZED
    wrap.__name__ = f.__name__
    return wrap

#random secret key 
app.secret_key = os.urandom(64)
csrf = CSRFProtect(app)

@app.route('/')
def home():

    if __name__ == '__main__':
        app.run()

    return redirect(url_for('register'))


@app.route('/register', methods=['POST', 'GET'])
def register():
    success = ' '
    if request.method == 'POST':
        user = request.form['uname']
        pwd = pbkdf2_sha256.hash(request.form['pword'])
        #pwd = request.form['pword']
        mfa = request.form['2fa']
        if (db.session.query(User.id).filter_by(username=user).scalar() is None):
            db.session.add(User(username=user, password=pwd, twofa=mfa))
            db.session.commit()
            success = 'success'
        else:
            success = 'failure'
            #flash('Failure')
    return render_template('register.html', success=success)


@app.route('/login', methods=['POST', 'GET'])
def login():
    result = ' ' 
    if request.method == 'POST':
        #verify login credentials
        provideduser = request.form['uname']
        #pwd = sha256_crypt.encrypt(request.form['pword'])
        providedpwd = request.form['pword']
        providedmfa = request.form['2fa']
        user = User.query.filter_by(username=provideduser).first()
        if (db.session.query(User.id).filter_by(username=provideduser).scalar() is None):
            result = 'Incorrect'
        elif not(pbkdf2_sha256.verify(str(providedpwd), user.password)):
        #elif pwd != Users[user]['pass']:
            result = 'Incorrect'
        elif providedmfa != user.twofa:
            result = 'Two-factor failure'
        else:
            #Set sessionID on success
            session['logged_in'] = True
            session['user'] = provideduser
            db.session.add(Logs(user_id=user.id, login=datetime.utcnow(), logout=None))
            db.session.commit()
            #add success message here
            result = 'success'
    return render_template('login.html', result=result)
    

@app.route('/spell_check', methods=['POST', 'GET'])
#@login_required
def spell_check():
    misspelled = None
    txt = None
    if request.method == 'POST':
        txt = request.form['inputtext']
        with open("input.txt", "w") as f:
            f.write(txt)
        check = subprocess.run(["./a.out", "input.txt", 'wordlist.txt'], stdout=subprocess.PIPE,)
        misspelled = check.stdout.decode('utf-8')
        misspelled.replace("\n",", ")
        user = session['user']
        active_user= User.query.filter_by(username=user).first()
        db.session.add(Query(user_id=active_user.id, submission=txt, results=misspelled))
        db.session.commit()
    return render_template('spell_check.html', txt=txt, misspelled=misspelled)


#route for logging out
@app.route('/logout')
@login_required
def logout():
    #edit active_user.Logs.logout.last()
    active_user = session['user']
    user = User.query.filter_by(username=active_user).first()
    currentsess = Logs.query.filter_by(user_id=user.id).first()
    currentsess.logout = datetime.utcnow()
    #remove sessionID on logout
    session.pop('logged_in', None)
    active_user = None
    currentsess=None
    flash('logged out')
    #redirect to home
    return redirect(url_for('login'))


@app.route('/history', methods=['POST', 'GET'])
#@login_required
def history():
    if 'logged_in' in session:
        currentuser = session['user']
        user = User.query.filter_by(username=currentuser).first()
        if request.method == 'POST':
            requestedusername = request.form['userquery']
            requesteduserdata = User.query.filter_by(username=requestedusername).first()
            chosenqueries = Query.query.filter_by(user_id=requesteduserdata.id).all()
            numqueries = len(chosenqueries)
            return render_template('queryhistory.html', queries=chosenqueries, user=user, numqueries=numqueries)
        else:
            queries = Query.query.filter_by(user_id=user.id).all()
            numqueries=len(queries)
            return render_template('queryhistory.html', queries=queries, user=user, numqueries=numqueries)
    else:
        errorMess = 'You need to login first.'
        return errorMess, status.HTTP_401_UNAUTHORIZED

@app.route('/history/query<int:querynum>')
#@login_required
def query(querynum):
    if 'logged_in' in session:
        currentuser = session['user']
        user = User.query.filter_by(username=currentuser).first()
        query = Query.query.filter_by(id=querynum).first()
        if ((query.bruser.id == user.id) or user.isadmin):
            numqueries = None
            return render_template('queryhistory.html', query=query, user=user, numqueries=numqueries)
        else:
            errorMess = 'You cannot view queries for other users.'
            return errorMess, status.HTTP_401_UNAUTHORIZED
    else:
        errorMess = 'You need to login first.'
        return errorMess, status.HTTP_401_UNAUTHORIZED

@app.route('/login_history', methods=['POST', 'GET'])
#@admin_required
def login_history():
    logs = []
    if request.method == 'POST':
        requesteduser = request.form['userid']
        user = User.query.filter_by(username=requesteduser).first()
        logs = Logs.query.filter_by(user_id=user.id).all()
    return render_template('log_history.html', logs=logs)



