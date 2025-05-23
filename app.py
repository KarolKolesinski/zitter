
from flask import Flask, render_template, session, request, redirect, url_for
from authlib.integrations.flask_client import OAuth
import os
from dotenv import load_dotenv
import random
import string

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or 'your-secret-key-here'  # Change this!

# Configure Google OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={
        'scope': 'openid email profile',
        'token_endpoint_auth_method': 'client_secret_post'
    },
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
)
# Przykładowa "baza danych" użytkowników
users = {}

def generate_username(email):
    # Extract username part from email
    base_username = email.split('@')[0]
    username = base_username
    
    # If username exists, add random digits
    if username in users:
        random_digits = ''.join(random.choices(string.digits, k=4))
        username = f"{base_username}-{random_digits}"
    
    return username

@app.route('/')
def strona_glowna():
    return render_template('home.html', title="Home")

@app.route('/profile')
def profile():
    if 'username' in session:
        return render_template('profile.html', 
                            title="Profile",
                            logged_in=True,
                            user={'username': session['username']})
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users and users[username]['password'] == password:
            session['username'] = username
            return redirect(url_for('profile'))
        return render_template('login.html', error="Nieprawidłowa nazwa użytkownika lub hasło")
    
    return render_template('login.html', title="Logowanie")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users:
            return render_template('register.html', error="Nazwa użytkownika już istnieje")
        
        users[username] = {'password': password}
        session['username'] = username
        return redirect(url_for('profile'))
    
    return render_template('register.html', title="Rejestracja")

@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/google/authorize')
def google_authorize():
    try:
        token = google.authorize_access_token()
        if token is None:
            return redirect(url_for('login'))
        
        # Verify and get user info
        resp = google.get('userinfo')
        if resp.status_code != 200:
            return redirect(url_for('login'))
        
        user_info = resp.json()
        email = user_info.get('email')
        if not email:
            return redirect(url_for('login'))
        
        username = generate_username(email)
        users[username] = {'google_auth': True}
        session['username'] = username
        
        return redirect(url_for('profile'))
    except Exception as e:
        print(f"Error during Google auth: {str(e)}")
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('strona_glowna'))

if __name__ == '__main__':
    app.run(debug=True)

    