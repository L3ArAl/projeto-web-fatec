from flask import flask

@app.route("/")
def home():
    return render_template("pcs.html")

# Página sobre
@app.route("/teste123")
def sobre():
    return render_template("teste.html")

# Página contato
@app.route("/euseila")
def contato():
    return render_template("/pasta_de_teste/sei_la.html")


if __name__ == "__main__":
    app.run(debug=True)