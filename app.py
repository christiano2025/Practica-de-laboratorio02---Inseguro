"""Aplicación Insegura"""
import os
from functools import wraps

import mysql.connector
from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, url_for

load_dotenv()
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "solo-desarrollo-local")


def get_db():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "proyecto_a_vulnerable"),
    )


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        # El cursor buffered permite cerrar la consulta aunque una inyección
        # educativa devuelva más de un usuario y solo leamos el primero.
        cursor = db.cursor(dictionary=True, buffered=True)
        # VULNERABLE: concatenación directa usada únicamente con fines educativos.
        query = (
            "SELECT id, username FROM usuarios WHERE username = '"
            + username
            + "' AND password = '"
            + password
            + "'"
        )
        try:
            cursor.execute(query)
            user = cursor.fetchone()
        except mysql.connector.Error:
            user = None
        finally:
            cursor.close()
            db.close()
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))
        flash("Credenciales incorrectas.", "danger")
    return render_template("login.html")


@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        cursor = db.cursor()
        # VULNERABLE: contraseña en texto plano y SQL concatenado.
        query = "INSERT INTO usuarios (username, password) VALUES ('" + username + "', '" + password + "')"
        try:
            cursor.execute(query)
            db.commit()
            flash("Usuario registrado. La contraseña quedó en texto plano.", "warning")
            return redirect(url_for("login"))
        except mysql.connector.Error:
            db.rollback()
            flash("No se pudo registrar el usuario.", "danger")
        finally:
            cursor.close()
            db.close()
    return render_template("registro.html")


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT p.*, u.username FROM publicaciones p JOIN usuarios u ON u.id = p.autor_id ORDER BY p.id DESC")
    publicaciones = cursor.fetchall()
    cursor.close()
    db.close()
    return render_template("dashboard.html", publicaciones=publicaciones)


@app.route("/publicaciones/nueva", methods=["POST"])
@login_required
def nueva_publicacion():
    titulo = request.form.get("titulo", "")
    contenido = request.form.get("contenido", "")
    db = get_db()
    cursor = db.cursor()
    # VULNERABLE: sin token CSRF, sin sanitización y con concatenación SQL.
    query = "INSERT INTO publicaciones (titulo, contenido, autor_id) VALUES ('" + titulo + "', '" + contenido + "', " + str(session["user_id"]) + ")"
    try:
        cursor.execute(query)
        db.commit()
    except mysql.connector.Error:
        db.rollback()
        flash("No se pudo guardar la publicación.", "danger")
    finally:
        cursor.close()
        db.close()
    return redirect(url_for("dashboard"))


@app.route("/publicaciones/<int:post_id>/eliminar")
@login_required
def eliminar_publicacion(post_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM publicaciones WHERE id = " + str(post_id))
    db.commit()
    cursor.close()
    db.close()
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
