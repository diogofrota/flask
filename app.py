from flask import Flask, render_template, request,session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "super-secret-key"

# Configuração da coneção com o banco de dados:
app.config["SQLALCHEMY_DATABASE_URI"] = ("postgresql://diogofrota@localhost/flask_lab")

# Aqui criamos um objeto chamado `db`
db = SQLAlchemy(app)

# usei essa classe para criar uma tabela via terminal do app shell do python
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)


# simula nosso banco de dados.
usuarios = {
    "admin": {
        "senha": "1234",
        "role": "admin"
    },
    "diogo": {

        "senha": "abcd",
        "role": "user"
    }
}

@app.route("/")
def home():
    # return "Olá, Flask!"
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Para lista locais de usuarios:
        #if username in usuarios and usuarios[username]["senha"] == password:
        #    session["usuario"] = username
        #    session["role"] = usuarios[username]["role"]

        usuario = Usuario.query.filter_by(username=username).first()

        # modo do if sem hash
        #if usuario and usuario.password == password:
        if usuario and check_password_hash(usuario.password, password):
            session["usuario"] = usuario.username
            session["role"] = usuario.role

            if session["role"] == "admin":
                return redirect(url_for("admin"))

            return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():

    if "usuario" not in session:
        return redirect(url_for("login"))

    # Leva o nome do usurio junto para o dashboard
    return render_template(
        "dashboard.html",
        usuario=session["usuario"]
    )

# Rota baseada em role
@app.route("/admin")
def admin():

    if "usuario" not in session:
        return redirect(url_for("login"))

    if session["role"] != "admin":
        return "Acesso negado", 403

    return render_template("painel_admin.html", usuario=session["usuario"])


@app.route("/usuarios")
def listar_usuarios():

    if "usuario" not in session:
        return redirect(url_for("login"))

    usuarios = Usuario.query.all()

    return render_template(
        "usuarios.html",
        usuarios=usuarios
    )

@app.route("/usuarios/novo", methods=["GET", "POST"])
def novo_usuario():

    if "usuario" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form["role"]

        usuario_existente = Usuario.query.filter_by(username=username).first()

        if usuario_existente:
            return "Usuário já existe"

        usuario = Usuario(
            username=username,
            password=generate_password_hash(
                password,
                method="pbkdf2:sha256"
            ),
            role=role
        )

        db.session.add(usuario)
        db.session.commit()

        return redirect(url_for("listar_usuarios"))

    return render_template("novo_usuario.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))



