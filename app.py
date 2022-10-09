from functools import wraps
from bson.objectid import ObjectId
import datetime
from flask import Flask, render_template, jsonify, request, redirect, session, abort, flash
from flask_session import Session
from passlib.hash import pbkdf2_sha256
import pymongo
from config import Config, db

app = Flask("Sleep Tracker With Slimes")
app.config.from_object(Config)
Session(app)

def login_required(something):
    @wraps(something)
    def wrap_login(*args, **kwargs):
        if 'logged_in' in session and session["logged_in"]:
            return something(session['logged_in_id'], *args, **kwargs)
        else:
            flash("Please Sign In First", category="danger")
            return redirect('/')
    return wrap_login

### WEBPAGE ROUTES ###
@app.route('/home', methods=['GET'])
def home():
    return render_template('home.html')

@app.route('/draw', methods=['GET'])
def draw():
    return render_template('draw.html')

@app.route('/info', methods=['GET'])
def info():
    return render_template('info.html')

@app.route('/calculator', methods=['GET'])
def calculator():     
    return render_template('calculator.html')

@app.route('/meditation', methods=['GET'])
def meditation():
    if request.method == 'GET':     
        return render_template('meditation.html')

@app.route('/tracker', methods=['GET'])
def tracker():
    users = db.users
    user = users.find_one({'_id': ObjectId(session['logged_in_id'])})
    user['_id'] = str(user['_id'])

    log = user['log']
    print(log)
    
    return render_template('tracker.html', log=log)

@app.route('/dashboard', methods=['GET'])
def dashboard():  
    return render_template('dashboard.html')

### API ROUTES ###

@app.route('/api/login', methods=['POST'])
def login():
    if request.method == 'POST':
        username=request.get_json()['username']
        password=request.get_json()['password']
        users = db.users
        user = users.find_one({
            'username': username,
        })
        if user is not None and pbkdf2_sha256.verify(password, user['password_hash']):
            session['logged_in'] = True
            session['logged_in_id'] = str(user['_id'])
            flash('Successful Login', category='success')
            return jsonify({'redirect': '/tracker'})
        else:
            if user is None:
                return jsonify({"error": "1", "message": "invalid username"})
            else:
                return jsonify({"error": "2", "message": "incorrect password"})
    return redirect('/')

@app.route('/api/signup', methods=['POST'])
def signup():
    if request.method == 'POST':
        print(request.json)
        print('data', request.data)
        username=request.get_json()['username']
        password=request.get_json()['password']
        cpassword=request.get_json()['confirm_password']
        users = db.users

        if users.find_one({'username': username}) is None:
            print("hello")
            if password == cpassword:
                newUser = {
                    "username": username,
                    "password_hash": pbkdf2_sha256.hash(password),
                    "log": [],
                }
                users.insert_one(newUser)
                user = users.find_one({'username': username})
                session['logged_in'] = True
                session['logged_in_id'] = str(user['_id'])

                flash('Account Successfully Created', category='success')
                return jsonify({'redirect': '/tracker'})
            else:
                return jsonify({"error": "2", "message": "passwords do not match"})
        else:
            return jsonify({"error": "1", "message": "username already in use"})
    return redirect('/')

@app.route('/api/logout', methods=['GET','POST'])
@login_required
def logout(uid):
    session['logged_in'] = False
    session['logged_in_id'] = ''
    return redirect('/')

@app.route('/api/log', methods=['POST'])
def log():
    print(request.json)
    print('data', request.data)
    date=request.get_json()['date']
    sleep_time=request.get_json()['sleep_time']
    wake_time=request.get_json()['wake_time']
    users = db.users
    user = users.find_one({'_id': ObjectId(session['logged_in_id'])})

    log = user['log']
    print(log)
    log.append({"date": date, "sleep_time": sleep_time, "wake_time": wake_time})
    print(log)
    users.update_one({'_id': ObjectId(session['logged_in_id'])}, {
                    '$set': {'log': log}})
    return jsonify({'error': 0, 'redirect': '/tracker'})

if __name__ == "__main__":
    app.config['SECRET_KEY'] = '123qwi34iWge9era89F1393h3gwJ0q3'
    app.run(debug=True)