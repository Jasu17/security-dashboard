import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"log", "txt"}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

def allowed_file(filename):
    if "." not in filename:
        return filename in {"auth.log", "syslog"}
    return filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files.get("logfile")

    if not file or file.filename == "":
        flash("No se selecciono ningun archivo.", "danger")
        return redirect(url_for("index"))

    if not allowed_file(file.filename):
        flash("Extension no permitida. Usa .log, .txt, auth.log o syslog.", "danger")
        return redirect(url_for("index"))

    content = file.read()

    if len(content) == 0:
        flash("El archivo esta vacio.", "danger")
        return redirect(url_for("index"))
    
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    with open(filepath, "wb") as f:
        f.write(content)

    flash("Archivo subido correctamente.", "success")
    return redirect(url_for("index"))

if __name__ == '__main__':
    app.run(debug=True)