from flask import Flask, render_template, session, request, redirect, url_for
from authlib.integrations.flask_client import OAuth
import os
from dotenv import load_dotenv
import random
import string
from datetime import datetime

load_dotenv()


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or 'your-secret-key-here'

# Google OAuth config
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

# Pamięciowe "bazy danych"
users = {}
user_posts = {}  # {username: [posty]}
global_posts = []  # [posty]

def generate_username(email, is_google=False):
    base_username = email.split('@')[0]
    if is_google:
        return base_username  # Dla Google zwracamy czystą nazwę bez dodatkowych cyfr
    
    username = base_username
    if username in users:
        random_digits = ''.join(random.choices(string.digits, k=4))
        username = f"{base_username}-{random_digits}"
    return username

@app.route('/', methods=['GET', 'POST'])
def strona_glowna():
    if request.method == 'POST' and 'username' in session:
        title = request.form.get('title')
        content = request.form.get('content')
        if title and content:
            post = {
                'username': session['username'],
                'title': title,
                'content': content,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            global_posts.append(post)
            user_posts.setdefault(session['username'], []).append(post)
            return redirect(url_for('strona_glowna'))

    return render_template('home.html',
                           title="Strona główna",
                           logged_in=('username' in session),
                           username=session.get('username'),
                           posts=global_posts)

@app.route('/profile')
def profile():
    if 'username' in session:
        username = session['username']
        user_specific_posts = user_posts.get(username, [])
        return render_template('profile.html',
                               title="Profil",
                               logged_in=True,
                               user={'username': username},
                               posts=user_specific_posts)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and users[username].get('password') == password:
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

        resp = google.get('userinfo')
        if resp.status_code != 200:
            return redirect(url_for('login'))

        user_info = resp.json()
        email = user_info.get('email')
        if not email:
            return redirect(url_for('login'))

        username = generate_username(email, is_google=True)  # Dodajemy is_google=True
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
post_counter = 0
@app.route('/add_post', methods=['GET', 'POST'])
def add_post():
    global post_counter

    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        username = session['username']
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        post = {
            'id': post_counter,
            'username': username,
            'title': title,
            'content': content,
            'timestamp': timestamp,
            'likes': 0
        }

        global_posts.append(post)
        user_posts.setdefault(username, []).append(post)
        post_counter += 1

        return redirect(url_for('strona_glowna'))

    return render_template('add_post.html', title="Dodaj Post")

@app.route('/like_post/<int:post_id>', methods=['POST'])
def like_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    if 'liked_posts' not in session:
        session['liked_posts'] = []

    if post_id not in session['liked_posts']:
        # Znajdź post po id:
        for post in global_posts:
            if post['id'] == post_id:
                post['likes'] += 1
                session['liked_posts'].append(post_id)
                session.modified = True
                break

    return redirect(url_for('strona_glowna'))
if __name__ == '__main__':
    app.run(debug=True)

