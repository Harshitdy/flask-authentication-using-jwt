from flask import Flask, request, jsonify, make_response, render_template, session
import jwt
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = "ece2a5e5d78b40989e00e4bdb76ee82b"
 
def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({"Alert!": 'Token is missing'})
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({"Alert!": "Invalid Token!"})
    return decorated

# For Public
@app.get('/public')
def public():
    return 'For Public'

# For Authenticated
@app.route('/auth')
@token_required
def auth():
    return 'JWT is verified. Welcome to your Dashboard'

# Home page
@app.get('/')
def home():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        return 'Logged in Currently!'
    
# Login Route
@app.post('/login')
def login():
    if request.form['username'] and request.form['password'] == '123456':
        session['logged_in'] = True
        token = jwt.encode({
            'user': request.form['username'],
            'exp': str(datetime.utcnow() + timedelta(seconds=120))
        }, 
        app.config['SECRET_KEY'],
        # algorithm="HS256"
        )
        return jsonify({'token': token})
    else:
        return make_response('Unable to verify', 403, {'WWW-Authenticate': 'Basic realm:"Authentication Failed!'})
