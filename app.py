from flask import Flask, render_template, request, redirect, url_for, session
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "cle_secrete_change_moi"  # Nécessaire pour les sessions

# Connexion MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["restoDB"]
users = db["users"]

# --------------------------------------------------------
#   PAGE D'ACCUEIL
# --------------------------------------------------------
@app.route('/')
def index():
    # Page d'accueil publique — afficher les boxes disponibles
    boxes_cursor = db.box.find()
    boxes = []
    for b in boxes_cursor:
        boxes.append({
            "_id": str(b.get("_id")),
            "numero": b.get("numero"),
            "places": b.get("places"),
            "status": b.get("status"),
            "type": b.get("type"),
            "prix_horaire": b.get("prix_horaire")
        })
    return render_template("index.html", boxes=boxes, current_year=datetime.now().year)


@app.route('/reserve_box', methods=["POST"])
def reserve_box():
    # Nécessite connexion
    if "user" not in session:
        return redirect(url_for('login'))

    box_id = request.form.get('box_id')
    if not box_id:
        return redirect(url_for('index'))

    try:
        oid = ObjectId(box_id)
    except Exception:
        return redirect(url_for('index'))

    box = db.box.find_one({"_id": oid})
    if not box:
        return redirect(url_for('index'))

    if box.get('status') != 'libre':
        # Déjà réservé
        return redirect(url_for('index'))

    username = session['user']['username']
    db.box.update_one({"_id": oid}, {"$set": {"status": 'reservee', "reserved_by": username, "reserved_at": datetime.utcnow()}})
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    # Page réservée aux utilisateurs connectés
    if "user" in session:
        user = session["user"]
        return render_template("dashboard.html", user=user)
    return redirect(url_for('login'))

# --------------------------------------------------------
#   PAGE D'INSCRIPTION
# --------------------------------------------------------
@app.route('/register', methods=["GET", "POST"])
def register():
    message = None  # message d’erreur éventuel

    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        role = "client"

        # Vérifie si l'utilisateur existe déjà
        existing_user = (
            users.find_one({"username": username}) or
            db.clients.find_one({"username": username}) or
            db.clients.find_one({"email": email})
        )

        if existing_user:
            message = "Nom d'utilisateur ou e-mail déjà utilisé."
        else:
            hashed_pw = generate_password_hash(password)
            db.clients.insert_one({
                "username": username,
                "email": email,
                "password": hashed_pw,
                "role": role
            })
            return redirect(url_for("login"))

    return render_template("register.html", message=message)

# --------------------------------------------------------
#   PAGE DE CONNEXION
# --------------------------------------------------------
@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = users.find_one({"username": username})
        if user and check_password_hash(user["password"], password):
            session["user"] = {
                "username": user["username"],
                "role": user["role"]
            }
            # Après connexion, rediriger vers le tableau de bord
            return redirect(url_for("dashboard"))
        else:
            return "Identifiants invalides"

    return render_template("login.html")

# --------------------------------------------------------
#   PAGE DE DÉCONNEXION
# --------------------------------------------------------
@app.route('/logout')
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))

# --------------------------------------------------------
#   FONCTION POUR CRÉER UN ADMIN (exécutée 1 fois)
# --------------------------------------------------------
@app.cli.command("create-admin")
def create_admin():
    """Créer un compte administrateur (commande Flask CLI)"""
    username = input("Nom d'utilisateur admin : ")
    password = input("Mot de passe : ")
    if users.find_one({"username": username}):
        print("Cet utilisateur existe déjà.")
        return
    hashed_pw = generate_password_hash(password)
    users.insert_one({"username": username, "password": hashed_pw, "role": "admin"})
    print("✅ Admin créé avec succès.")

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
