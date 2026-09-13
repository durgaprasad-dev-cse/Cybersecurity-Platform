from flask import Flask, render_template, request
from port_scanner import port_scanner

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")

# ===== CYBER AWARENESS =====
@app.route("/awareness")
def awareness():
    return render_template("awareness.html")

# ===== PHISHING DEMO (FIXED) =====
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

    return render_template("phishing_demo.html", captured=captured)

# ===== PASSWORD STRENGTH =====
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

    return render_template("password_strength.html", strength=strength)

# ===== PASSWORD GENERATOR =====
@app.route("/password-generator")
def password_generator():
    return render_template("password_generator.html")

# ===== PORT SCANNER =====
@app.route("/portscan", methods=["GET", "POST"])
def portscan():
    open_ports = []
    target = ""

    if request.method == "POST":
        target = request.form["target"]
        open_ports = port_scanner(target)

    return render_template("portscan.html", target=target, open_ports=open_ports)

if __name__ == "__main__":
    app.run(debug=True)