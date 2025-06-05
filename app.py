import os
import random
import string
from datetime import datetime
from flask import Flask, render_template, session, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or 'your-secret-key-here'

# Użyj absolutnej ścieżki do pliku bazy danych
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(basedir, 'baza.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Konfiguracja OAuth dla Google
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
)

# MODELE
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(200))
    google_auth = db.Column(db.Boolean, default=False)
    profile_picture = db.Column(db.String(200), default='default_avatar.png')
    posts = db.relationship('Post', backref='author', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    likes = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_like'),)


# FUNKCJE POMOCNICZE
def generate_username(email, is_google=False):
    base_username = email.split('@')[0]
    user = User.query.filter_by(username=base_username).first()
    if user:
        random_digits = ''.join(random.choices(string.digits, k=4))
        return f"{base_username}-{random_digits}"
    return base_username


# ROUTY
@app.route('/')
def strona_glowna():
    posts = Post.query.order_by(Post.timestamp.desc()).all()
    user_likes = []
    if 'user_id' in session:
        user_id = session['user_id']
        user_likes = [like.post_id for like in Like.query.filter_by(user_id=user_id).all()]
    return render_template('home.html', title="Strona główna", logged_in=('username' in session),
                           username=session.get('username'), posts=posts, user_likes=user_likes)

@app.route('/profile')
def profile():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        if user:
            return render_template('profile.html', title="Profil", logged_in=True,
                                   user=user, posts=user.posts)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['username'] = username
            session['user_id'] = user.id
            return redirect(url_for('profile'))
        return render_template('login.html', error="Nieprawidłowa nazwa użytkownika lub hasło")
    return render_template('login.html', title="Logowanie")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error="Nazwa użytkownika już istnieje")
        hashed_pw = generate_password_hash(password)
        user = User(username=username, password_hash=hashed_pw)
        db.session.add(user)
        db.session.commit()
        session['username'] = username
        session['user_id'] = user.id
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
        username = generate_username(email, is_google=True)
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username, google_auth=True)
            db.session.add(user)
            db.session.commit()
        session['username'] = username
        session['user_id'] = user.id
        return redirect(url_for('profile'))
    except Exception as e:
        print(f"Error during Google auth: {str(e)}")
        return redirect(url_for('login'))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route('/add_post', methods=['GET', 'POST'])
def add_post():
    if 'username' not in session or 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        post = Post(title=title, content=content, user_id=session['user_id'])
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('strona_glowna'))
    return render_template('add_post.html', title="Dodaj Post")

@app.route('/search_users', methods=['GET'])
def search_users():
    query = request.args.get('q', '')
    users = User.query.filter(User.username.ilike(f"%{query}%")).all() if query else []
    return render_template('user_results.html', title="Wyniki użytkowników", query=query, users=users)

@app.route('/like/<int:post_id>', methods=['POST'])
def like_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    if Like.query.filter_by(user_id=user_id, post_id=post_id).first():
        return redirect(url_for('strona_glowna'))
    post = Post.query.get(post_id)
    if not post or post.user_id == user_id:
        return redirect(url_for('strona_glowna'))
    like = Like(user_id=user_id, post_id=post_id)
    post.likes += 1
    db.session.add(like)
    db.session.commit()
    return redirect(url_for('strona_glowna'))

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        return redirect(url_for('login'))
    if request.method == 'POST':
        new_username = request.form['username']
        image = request.files.get('profile_picture')
        if new_username != user.username:
            if User.query.filter_by(username=new_username).first():
                return render_template('edit_profile.html', user=user, error="Nazwa użytkownika już istnieje")
            user.username = new_username
            session['username'] = new_username
        if image and image.filename != '':
            filename = secure_filename(image.filename)
            filepath = os.path.join('static/images', filename)
            image.save(filepath)
            user.profile_picture = filename
        db.session.commit()
        return redirect(url_for('profile'))
    return render_template('edit_profile.html', user=user, title="Edytuj Profil")


# URUCHOMIENIE APLIKACJI
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
