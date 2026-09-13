from flask import Flask, render_template, request,session, redirect, url_for, flash
#funcão para o decorador:
from functools import wraps
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
@login_required # -> coloquei so no listar usurio para servir de exemplo.
def listar_usuarios():

    # vou tirar essa funcao so para colocar o decorador
#   if "usuario" not in session:
#       return redirect(url_for("login"))

    usuarios = Usuario.query.all()

    return render_template(
        "usuarios.html",
        usuarios=usuarios
    )

@app.route("/novo_usuario", methods=["GET", "POST"])
def novo_usuario():

    # caso usuario não estaja logado
    if "usuario" not in session:
        return redirect(url_for("login"))

    # pega os dados do post
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form["role"]

        usuario_existente = Usuario.query.filter_by(username=username).first()

        #  verifica se tem registro
        if usuario_existente:
            flash("Usuário já existe.", "error") # msg usuario exitente.
            return "Usuário já existe"

        # instancia da classe usuraio ( lembrando que esta com U maisculo )
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

        flash("Usuário cadastrado com sucesso.", "success")

        return redirect(url_for("listar_usuarios"))

    return render_template("novo_usuario.html")

@app.route("/usuarios/<int:id>/editar", methods=["GET", "POST"])
def editar_usuario(id):

    # Bloqueia quem não está logado
    if "usuario" not in session:
        return redirect(url_for("login"))

    # Busca o usuário pelo ID
    usuario = Usuario.query.get_or_404(id)

    # Processa o formulário enviado
    if request.method == "POST":
        usuario.username = request.form["username"]
        usuario.role = request.form["role"]

        # Atualiza a senha somente se uma nova senha for digitada
        nova_senha = request.form["password"]

        if nova_senha:
            usuario.password = generate_password_hash(
                nova_senha,
                method="pbkdf2:sha256"
            )

        # Salva as alterações no banco
        db.session.commit()

        # Cria mensagem de sucesso
        flash("Usuário atualizado com sucesso.", "success")

        return redirect(url_for("listar_usuarios"))

    # Mostra o formulário com os dados atuais
    return render_template(
        "editar_usuario.html",
        usuario=usuario
    )


@app.route("/usuarios/<int:id>/excluir", methods=["POST"])
def excluir_usuario(id):

    # Bloqueia quem não está logado
    if "usuario" not in session:
        return redirect(url_for("login"))

    # Busca o usuário pelo ID
    usuario = Usuario.query.get_or_404(id)

    # Remove o usuário da sessão do banco
    db.session.delete(usuario)

    # Confirma a exclusão no PostgreSQL
    db.session.commit()

    # Cria mensagem de sucesso
    flash("Usuário excluído com sucesso.", "success")

    return redirect(url_for("listar_usuarios"))


# Protege rotas que exigem login
def login_required(funcao):

    @wraps(funcao)
    def verificar_login(*args, **kwargs):

        if "usuario" not in session:
            return redirect(url_for("login"))

        return funcao(*args, **kwargs)

    return verificar_login



@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))



