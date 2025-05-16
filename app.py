from flask import Flask, render_template

app = Flask(__name__)

@app.route('/strona_glowna')
def strona_glowna():
    return render_template('home.html', title = "Strona główna")

@app.route('/wlasne_przepisy')

def wlasne_przepisy():
    return render_template('wlasne_przepisy.html', title = "Własne przepisy")

@app.route('/galeria')
def galeria():
    return render_template('about.html', title = "Galeria")


if __name__ == '__main__':
    app.run(debug=True)
