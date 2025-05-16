from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def strona_glowna():
    return render_template('home.html', title = "Home")

@app.route('/profile')

def profile():
    return render_template('profile.html', title = "Profile")

if __name__ == '__main__':
    app.run(debug=True)
