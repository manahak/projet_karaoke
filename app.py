from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "cle_secrete_change_moi"  # Nécessaire pour les sessions


@app.context_processor
def inject_current_year():
    return { 'current_year': datetime.now().year }

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


@app.route('/reserve_prepare', methods=["POST"])
def reserve_prepare():
    # Collect reservation details from the user and store in session.
    box_id = request.form.get('box_id')
    date = request.form.get('date')
    heure_debut = request.form.get('heure_debut')
    heure_fin = request.form.get('heure_fin')
    notes = request.form.get('notes')

    if not box_id or not date or not heure_debut or not heure_fin:
        return redirect(url_for('index'))

    # Basic validation of ObjectId
    try:
        ObjectId(box_id)
    except Exception:
        return redirect(url_for('index'))

    session['pending_reservation'] = {
        'box_id': box_id,
        'date': date,
        'heure_debut': heure_debut,
        'heure_fin': heure_fin,
        'notes': notes or ''
    }

    # If user not logged in, ask them to login first and then continue to confirmation
    if 'user' not in session:
        session['post_login_redirect'] = url_for('confirm_reservation')
        return redirect(url_for('login'))

    return redirect(url_for('confirm_reservation'))


@app.route('/confirm_reservation', methods=['GET'])
def confirm_reservation():
    pending = session.get('pending_reservation')
    if not pending:
        return redirect(url_for('index'))

    # Fetch box details for display
    try:
        box = db.box.find_one({'_id': ObjectId(pending['box_id'])})
    except Exception:
        return redirect(url_for('index'))

    if not box:
        return redirect(url_for('index'))

    return render_template('confirm_reservation.html', pending=pending, box={
        '_id': str(box.get('_id')),
        'numero': box.get('numero'),
        'places': box.get('places'),
        'type': box.get('type'),
        'prix_horaire': box.get('prix_horaire')
    })


@app.route('/reservation_create', methods=['POST'])
def reservation_create():
    # Finalize reservation: user must be authenticated
    if 'user' not in session:
        session['post_login_redirect'] = url_for('confirm_reservation')
        return redirect(url_for('login'))

    pending = session.get('pending_reservation')
    if not pending:
        return redirect(url_for('index'))

    try:
        user_oid = ObjectId(session['user']['user_id'])
        box_oid = ObjectId(pending['box_id'])
    except Exception:
        return redirect(url_for('index'))

    # Check box availability again
    box = db.box.find_one({'_id': box_oid})
    if not box or box.get('status') != 'libre':
        # Box not available
        session.pop('pending_reservation', None)
        return redirect(url_for('index'))

    reservation_doc = {
        'user_id': user_oid,
        'box_id': box_oid,
        'date': pending['date'],
        'heure_debut': pending['heure_debut'],
        'heure_fin': pending['heure_fin'],
        'status': 'en_attente',
        'notes': pending.get('notes', ''),
        'created_at': datetime.utcnow()
    }

    db.reservation.insert_one(reservation_doc)

    # Mark box as reserved to prevent double booking
    db.box.update_one({'_id': box_oid}, {'$set': {'status': 'reservee', 'reserved_by': session['user']['username'], 'reserved_at': datetime.utcnow()}})

    # Cleanup
    session.pop('pending_reservation', None)
    session.pop('post_login_redirect', None)

    # Flash a thank-you banner message
    flash('Merci de votre réservation !', 'success')
    return redirect(url_for('dashboard'))


@app.route('/dashboard')
def dashboard():
    # Page réservée aux utilisateurs connectés
    if "user" in session:
        user = session["user"]
        # Récupérer les réservations de l'utilisateur
        reservations = []
        try:
            user_oid = ObjectId(user.get('user_id'))
            cursor = db.reservation.find({'user_id': user_oid}).sort('created_at', -1)
            for r in cursor:
                # obtenir numéro de box si disponible
                box = db.box.find_one({'_id': r.get('box_id')}) if r.get('box_id') else None
                reservations.append({
                    '_id': str(r.get('_id')),
                    'box_numero': box.get('numero') if box else None,
                    'date': r.get('date'),
                    'heure_debut': r.get('heure_debut'),
                    'heure_fin': r.get('heure_fin'),
                    'status': r.get('status'),
                    'notes': r.get('notes', '')
                })
        except Exception:
            reservations = []

        return render_template("dashboard.html", user=user, reservations=reservations)
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
            # Store user info and id in session for later use
            session["user"] = {
                "username": user["username"],
                "role": user["role"],
                "user_id": str(user.get("_id"))
            }
            # If there is a post-login redirect (reservation flow), follow it
            redirect_target = session.pop('post_login_redirect', None)
            if redirect_target:
                return redirect(redirect_target)
            # Sinon, rediriger vers le tableau de bord
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
