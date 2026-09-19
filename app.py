import os
import uuid

from flask import Flask, render_template, request

from scam_agent import analyze_scam
from port_scanner import port_scanner
from url_analyzer import analyze_url
from file_analyzer import analyze_file
from password_security import (
    analyze_password,
    generate_strong_password
)
from apk_analyzer import analyze_apk


# =========================================================
# FLASK APPLICATION
# =========================================================

app = Flask(__name__)


# =========================================================
# UPLOAD CONFIGURATION
# =========================================================

UPLOAD_FOLDER = "uploads"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

app.config["MAX_CONTENT_LENGTH"] = (
    10 * 1024 * 1024
)

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)


# =========================================================
# HOME
# =========================================================

@app.route("/")
def index():

    return render_template(
        "index.html"
    )


# =========================================================
# CYBER AWARENESS
# =========================================================

@app.route("/awareness")
def awareness():

    return render_template(
        "awareness.html"
    )


# =========================================================
# PHISHING DEMO
# =========================================================

@app.route(
    "/phishing",
    methods=["GET", "POST"]
)
def phishing():

    captured = None

    if request.method == "POST":

        username = request.form.get(
            "username"
        )

        password = request.form.get(
            "password"
        )

        captured = {
            "username": username,
            "password": password
        }

    return render_template(
        "phishing_demo.html",
        captured=captured
    )


# =========================================================
# PASSWORD SECURITY
# =========================================================

@app.route(
    "/password-security",
    methods=["GET", "POST"]
)
def password_security():

    result = None

    if request.method == "POST":

        password = request.form.get(
            "password",
            ""
        )

        result = analyze_password(
            password
        )

    return render_template(
        "password_security.html",
        result=result
    )


# =========================================================
# PASSWORD GENERATOR
# =========================================================

@app.route(
    "/password-generator"
)
def password_generator():

    password = generate_strong_password()

    return render_template(
        "password_generator.html",
        password=password
    )


@app.route(
    "/generate-password"
)
def generate_password():

    password = generate_strong_password()

    return {
        "password": password
    }


# =========================================================
# PORT SCANNER
# =========================================================

@app.route(
    "/portscan",
    methods=["GET", "POST"]
)
def portscan():

    open_ports = []

    target = ""

    if request.method == "POST":

        target = request.form.get(
            "target",
            ""
        ).strip()

        if target:

            open_ports = port_scanner(
                target
            )

    return render_template(
        "portscan.html",
        target=target,
        open_ports=open_ports
    )


# =========================================================
# URL & FILE SAFETY ANALYZER
# =========================================================

@app.route(
    "/url-analyzer",
    methods=["GET", "POST"]
)
def url_analyzer():

    result = None

    if request.method == "POST":

        analysis_type = request.form.get(
            "analysis_type"
        )

        # -------------------------------------------------
        # URL ANALYSIS
        # -------------------------------------------------

        if analysis_type == "url":

            url = request.form.get(
                "url",
                ""
            ).strip()

            if url:

                result = analyze_url(
                    url
                )

        # -------------------------------------------------
        # GENERAL FILE ANALYSIS
        # -------------------------------------------------

        elif analysis_type == "file":

            uploaded_file = request.files.get(
                "file"
            )

            if (
                uploaded_file
                and uploaded_file.filename
            ):

                original_filename = (
                    uploaded_file.filename
                )

                extension = os.path.splitext(
                    original_filename
                )[1].lower()

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

                if extension not in allowed_extensions:

                    result = {

                        "risk_level": "SUSPICIOUS",

                        "risk_score": 3,

                        "filename": original_filename,

                        "extension": extension,

                        "size": 0,

                        "sha256": "Not calculated",

                        "indicators": [
                            (
                                "This file extension is "
                                "not currently supported."
                            )
                        ]
                    }

                else:

                    safe_filename = (
                        str(uuid.uuid4())
                        + extension
                    )

                    file_path = os.path.join(
                        app.config["UPLOAD_FOLDER"],
                        safe_filename
                    )

                    uploaded_file.save(
                        file_path
                    )

                    try:

                        result = analyze_file(
                            file_path,
                            original_filename
                        )

                    finally:

                        if os.path.exists(
                            file_path
                        ):

                            os.remove(
                                file_path
                            )

    return render_template(
        "url_analyzer.html",
        result=result
    )


# =========================================================
# APK ANALYZER
# =========================================================

@app.route(
    "/apk-analyzer",
    methods=["GET", "POST"]
)
def apk_analyzer():

    result = None

    if request.method == "POST":

        uploaded_file = request.files.get(
            "apk_file"
        )

        if (
            uploaded_file
            and uploaded_file.filename
        ):

            original_filename = (
                uploaded_file.filename
            )

            extension = os.path.splitext(
                original_filename
            )[1].lower()

            # -------------------------------------------------
            # INVALID FILE TYPE
            # -------------------------------------------------

            if extension != ".apk":

                result = {

                    "filename": original_filename,

                    "risk_level": "INVALID",

                    "risk_score": 0,

                    "indicators": [
                        "Please upload a valid .apk file."
                    ],

                    "virustotal": None,

                    "virustotal_message": (
                        "VirusTotal was not contacted."
                    )
                }

            # -------------------------------------------------
            # APK ANALYSIS
            # -------------------------------------------------

            else:

                safe_filename = (
                    str(uuid.uuid4())
                    + ".apk"
                )

                file_path = os.path.join(
                    app.config["UPLOAD_FOLDER"],
                    safe_filename
                )

                uploaded_file.save(
                    file_path
                )

                try:

                    result = analyze_apk(
                        file_path,
                        original_filename
                    )

                except Exception as error:

                    result = {

                        "filename": original_filename,

                        "risk_level": "ANALYSIS ERROR",

                        "risk_score": 0,

                        "indicators": [
                            f"APK analysis failed: {error}"
                        ],

                        "virustotal": None,

                        "virustotal_message": (
                            "VirusTotal analysis "
                            "was not completed."
                        )
                    }

                finally:

                    if os.path.exists(
                        file_path
                    ):

                        os.remove(
                            file_path
                        )

    return render_template(
        "apk_analyzer.html",
        result=result
    )


# =========================================================
# CYBER SCAM HELP CENTER
# =========================================================

@app.route(
    "/scam-help",
    methods=["GET", "POST"]
)
def scam_help():

    result = None
    error = None

    if request.method == "POST":

        description = request.form.get(
            "description",
            ""
        ).strip()

        category = request.form.get(
            "category",
            "Other / Unclear"
        )

        requested_actions = request.form.getlist(
            "requested_action"
        )

        user_action = request.form.get(
            "user_action",
            "I am not sure"
        )

        current_status = request.form.get(
            "current_status",
            "I am unsure"
        )

        try:

            result = analyze_scam(
                user_text=description,
                category=category,
                requested_actions=requested_actions,
                user_action=user_action,
                current_status=current_status
            )

        except ValueError as exc:

            error = str(exc)

        except RuntimeError as exc:

            error = str(exc)

        except Exception:

            error = (
                "The AI analysis could not be completed. "
                "Please try again."
            )

    return render_template(
        "scam_help.html",
        result=result,
        error=error
    )


# =========================================================
# APPLICATION START
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )