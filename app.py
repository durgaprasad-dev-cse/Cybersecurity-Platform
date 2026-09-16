import os
import uuid

from flask import Flask, render_template, request

from port_scanner import port_scanner
from url_analyzer import analyze_url
from file_analyzer import analyze_file


app = Flask(__name__)


# ============================================================
# UPLOAD CONFIGURATION
# ============================================================

UPLOAD_FOLDER = "uploads"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/")
def index():
    return render_template("index.html")


# ============================================================
# 1. CYBER AWARENESS
# ============================================================

@app.route("/awareness")
def awareness():
    return render_template("awareness.html")


# ============================================================
# 2. PHISHING DEMO
# ============================================================

@app.route("/phishing", methods=["GET", "POST"])
def phishing():

    captured = None

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        captured = {
            "username": username,
            "password": password
        }

    return render_template(
        "phishing_demo.html",
        captured=captured
    )


# ============================================================
# 3. PASSWORD STRENGTH
# ============================================================

@app.route("/password-strength", methods=["GET", "POST"])
def password_strength():

    strength = None

    if request.method == "POST":

        password = request.form.get("password")

        if len(password) < 6:

            strength = "Weak"

        elif len(password) < 10:

            strength = "Medium"

        else:

            strength = "Strong"

    return render_template(
        "password_strength.html",
        strength=strength
    )


# ============================================================
# 4. PASSWORD GENERATOR
# ============================================================

@app.route("/password-generator")
def password_generator():

    return render_template(
        "password_generator.html"
    )


# ============================================================
# 5. PORT SCANNER
# ============================================================

@app.route("/portscan", methods=["GET", "POST"])
def portscan():

    open_ports = []
    target = ""

    if request.method == "POST":

        target = request.form["target"]

        open_ports = port_scanner(target)

    return render_template(
        "portscan.html",
        target=target,
        open_ports=open_ports
    )


# ============================================================
# 6. URL & FILE SAFETY ANALYZER
# ============================================================

@app.route("/url-analyzer", methods=["GET", "POST"])
def url_analyzer():

    result = None

    if request.method == "POST":

        analysis_type = request.form.get(
            "analysis_type"
        )


        # ====================================================
        # URL ANALYSIS
        # ====================================================

        if analysis_type == "url":

            url = request.form.get(
                "url",
                ""
            ).strip()

            if url:

                result = analyze_url(url)


        # ====================================================
        # FILE / APK ANALYSIS
        # ====================================================

        elif analysis_type == "file":

            uploaded_file = request.files.get(
                "file"
            )

            if uploaded_file and uploaded_file.filename:

                original_filename = (
                    uploaded_file.filename
                )

                extension = os.path.splitext(
                    original_filename
                )[1].lower()


                # --------------------------------------------
                # Allowed file extensions
                # --------------------------------------------

                allowed_extensions = [

                    ".apk",

                    ".pdf",

                    ".zip",

                    ".txt",

                    ".doc",

                    ".docx",

                    ".jpg",

                    ".jpeg",

                    ".png",

                    ".exe",

                    ".dll",

                    ".bat",

                    ".cmd",

                    ".js",

                    ".vbs",

                    ".ps1",

                    ".sh"
                ]


                # --------------------------------------------
                # Unsupported file
                # --------------------------------------------

                if extension not in allowed_extensions:

                    result = {

                        "risk_level":
                            "SUSPICIOUS",

                        "risk_score":
                            3,

                        "filename":
                            original_filename,

                        "extension":
                            extension,

                        "size":
                            0,

                        "sha256":
                            "Not calculated",

                        "indicators": [

                            "This file extension "
                            "is not currently supported."

                        ]
                    }


                # --------------------------------------------
                # Supported file
                # --------------------------------------------

                else:

                    # Generate a random filename
                    # so the original filename is not
                    # directly used on the server.

                    safe_filename = (
                        str(uuid.uuid4())
                        + extension
                    )

                    file_path = os.path.join(

                        app.config[
                            "UPLOAD_FOLDER"
                        ],

                        safe_filename
                    )


                    # Save uploaded file

                    uploaded_file.save(
                        file_path
                    )


                    try:

                        result = analyze_file(

                            file_path,

                            original_filename
                        )

                    finally:

                        # ------------------------------------
                        # Delete uploaded file after analysis
                        # ------------------------------------

                        if os.path.exists(
                            file_path
                        ):

                            os.remove(
                                file_path
                            )


    # ========================================================
    # RETURN ANALYZER PAGE
    # ========================================================

    return render_template(

        "url_analyzer.html",

        result=result
    )


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )