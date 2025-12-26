from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "cle_secrete_change_moi"  # Nécessaire pour les sessions

# CSRF protection
csrf = CSRFProtect()
csrf.init_app(app)


@app.context_processor
def inject_current_year():
    # expose current year and csrf token generator to templates
    return { 'current_year': datetime.now().year, 'csrf_token': generate_csrf }

# Connexion MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["restoDB"]
users = db["users"]

# Définition des créneaux fixes (2 heures) entre 11:30 et 01:30 (dernier créneau 23:30-01:30)
SLOTS = [
    ("11:30", "13:30"),
    ("13:30", "15:30"),
    ("15:30", "17:30"),
    ("17:30", "19:30"),
    ("19:30", "21:30"),
    ("21:30", "23:30"),
    ("23:30", "01:30")
]

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
            # backend status left intact but not shown in UI per new requirement
            "status": b.get("status"),
            "type": b.get("type"),
            "prix_horaire": b.get("prix_horaire")
        })
    return render_template("index.html", boxes=boxes, current_year=datetime.now().year, slots=SLOTS)


@app.route('/reserve_prepare', methods=["POST"])
def reserve_prepare():
    # Collect reservation details from the user and store in session.
    box_id = request.form.get('box_id')
    date = request.form.get('date')
    slot_index = request.form.get('slot_index')
    notes = request.form.get('notes')

    if not box_id or not date or slot_index is None:
        return redirect(url_for('index'))

    # Basic validation of ObjectId and slot index
    try:
        ObjectId(box_id)
        slot_index = int(slot_index)
        if slot_index < 0 or slot_index >= len(SLOTS):
            return redirect(url_for('index'))
    except Exception:
        return redirect(url_for('index'))

    heure_debut, heure_fin = SLOTS[slot_index]

    session['pending_reservation'] = {
        'box_id': box_id,
        'date': date,
        'heure_debut': heure_debut,
        'heure_fin': heure_fin,
        'slot_index': slot_index,
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

    # Check slot availability again for the given date using overlap detection
    def parse_dt(date_str, time_str):
        # returns a datetime (date+time) for start; if time crosses midnight, we'll handle end separately
        parts = [int(p) for p in time_str.split(":")]
        from datetime import datetime as _dt, date as _date, time as _time
        d = _dt.strptime(date_str, "%Y-%m-%d").date()
        return _dt.combine(d, _time(parts[0], parts[1]))

    def overlaps(box_oid, target_date_str, start_str, end_str, exclude_id=None):
        from datetime import datetime as _dt, timedelta as _td
        target_start = parse_dt(target_date_str, start_str)
        target_end = parse_dt(target_date_str, end_str)
        if target_end <= target_start:
            target_end += _td(days=1)

        # check reservations on target_date and the previous date (to catch over-midnight overlaps)
        from datetime import datetime as _dt2
        d = _dt2.strptime(target_date_str, "%Y-%m-%d").date()
        prev = (d - _td(days=1)).strftime("%Y-%m-%d")
        dates_to_check = [target_date_str, prev]

        cursor = db.reservation.find({'box_id': box_oid, 'date': {'$in': dates_to_check}, 'status': {'$ne': 'annule'}})
        for r in cursor:
            if exclude_id and str(r.get('_id')) == str(exclude_id):
                continue
            r_start = parse_dt(r.get('date'), r.get('heure_debut'))
            r_end = parse_dt(r.get('date'), r.get('heure_fin'))
            if r_end <= r_start:
                r_end += _td(days=1)
            # intervals overlap?
            if not (target_end <= r_start or target_start >= r_end):
                return True
        return False

    if overlaps(box_oid, pending['date'], pending['heure_debut'], pending['heure_fin']):
        # Slot overlaps an existing reservation
        session.pop('pending_reservation', None)
        flash('Le créneau sélectionné est en conflit avec une réservation existante. Veuillez choisir un autre créneau.', 'error')
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

    # Do NOT change the global box.status — we track reservations per slot only

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


@app.route('/reservation_cancel', methods=['POST'])
def reservation_cancel():
    if 'user' not in session:
        return redirect(url_for('login'))
    res_id = request.form.get('reservation_id')
    if not res_id:
        return redirect(url_for('dashboard'))
    try:
        oid = ObjectId(res_id)
    except Exception:
        return redirect(url_for('dashboard'))

    res = db.reservation.find_one({'_id': oid})
    if not res:
        flash('Réservation introuvable.', 'error')
        return redirect(url_for('dashboard'))

    # allow cancel only by owner or admin
    user = session.get('user')
    if user.get('role') != 'admin' and str(res.get('user_id')) != user.get('user_id'):
        flash('Vous n\'êtes pas autorisé à annuler cette réservation.', 'error')
        return redirect(url_for('dashboard'))

    db.reservation.update_one({'_id': oid}, {'$set': {'status': 'annule', 'cancelled_at': datetime.utcnow()}})
    flash('Réservation annulée.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/reservation_modify/<res_id>', methods=['GET', 'POST'])
def reservation_modify(res_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    try:
        oid = ObjectId(res_id)
    except Exception:
        return redirect(url_for('dashboard'))

    res = db.reservation.find_one({'_id': oid})
    if not res:
        flash('Réservation introuvable.', 'error')
        return redirect(url_for('dashboard'))

    user = session.get('user')
    if user.get('role') != 'admin' and str(res.get('user_id')) != user.get('user_id'):
        flash('Vous n\'êtes pas autorisé à modifier cette réservation.', 'error')
        return redirect(url_for('dashboard'))

    box_oid = res.get('box_id')
    box = db.box.find_one({'_id': box_oid})
    if request.method == 'POST':
        # process modification
        date = request.form.get('date')
        slot_index = request.form.get('slot_index')
        notes = request.form.get('notes')
        if not date or slot_index is None:
            flash('Données invalides.', 'error')
            return redirect(url_for('reservation_modify', res_id=res_id))
        try:
            slot_index = int(slot_index)
            if slot_index < 0 or slot_index >= len(SLOTS):
                raise ValueError()
        except Exception:
            flash('Créneau invalide.', 'error')
            return redirect(url_for('reservation_modify', res_id=res_id))

        start, end = SLOTS[slot_index]
        # check overlap excluding current reservation
        def parse_dt(date_str, time_str):
            parts = [int(p) for p in time_str.split(":")]
            from datetime import datetime as _dt, date as _date, time as _time
            d = _dt.strptime(date_str, "%Y-%m-%d").date()
            return _dt.combine(d, _time(parts[0], parts[1]))

        from datetime import datetime as _dt, timedelta as _td
        target_start = parse_dt(date, start)
        target_end = parse_dt(date, end)
        if target_end <= target_start:
            target_end += _td(days=1)

        # overlap check similar to above
            prev = ( _dt.strptime(date, "%Y-%m-%d").date() - _td(days=1) ).strftime("%Y-%m-%d")
            cursor = db.reservation.find({'box_id': box_oid, 'date': {'$in': [date, prev]}, 'status': {'$ne': 'annule'}})
        conflict = False
        for r in cursor:
            if str(r.get('_id')) == res_id:
                continue
            r_start = parse_dt(r.get('date'), r.get('heure_debut'))
            r_end = parse_dt(r.get('date'), r.get('heure_fin'))
            if r_end <= r_start:
                r_end += _td(days=1)
            if not (target_end <= r_start or target_start >= r_end):
                conflict = True
                break

        if conflict:
            flash('Le créneau choisi est en conflit avec une réservation existante.', 'error')
            return redirect(url_for('reservation_modify', res_id=res_id))

        # update reservation
        db.reservation.update_one({'_id': oid}, {'$set': {'date': date, 'heure_debut': start, 'heure_fin': end, 'notes': notes}})
        flash('Réservation modifiée.', 'success')
        return redirect(url_for('dashboard'))

    # GET -> render modify page
    pending = {
        'box_id': str(box.get('_id')),
        'date': res.get('date'),
        'heure_debut': res.get('heure_debut'),
        'heure_fin': res.get('heure_fin'),
        'slot_index': next((i for i,(s,e) in enumerate(SLOTS) if s==res.get('heure_debut')), None),
        'notes': res.get('notes','')
    }
    return render_template('modify_reservation.html', reservation=res, box={'numero': box.get('numero'), 'prix_horaire': box.get('prix_horaire')}, pending=pending, slots=SLOTS)


@app.route('/api/availability')
def api_availability():
    # Returns list of reserved slot indexes for a given box and date
    box_id = request.args.get('box_id')
    date = request.args.get('date')
    if not box_id or not date:
        return jsonify({'error': 'missing parameters'}), 400

    try:
        box_oid = ObjectId(box_id)
    except Exception:
        return jsonify({'error': 'invalid box_id'}), 400

    reserved_indexes = []
    excluded = request.args.get('exclude_id')
    cursor = db.reservation.find({'box_id': box_oid, 'date': date, 'status': {'$ne': 'annule'}})
    for r in cursor:
        if excluded and str(r.get('_id')) == excluded:
            continue
        hd = r.get('heure_debut')
        # find matching slot index
        for idx, (sstart, send) in enumerate(SLOTS):
            if sstart == hd:
                reserved_indexes.append(idx)
                break

    return jsonify({'reserved': reserved_indexes})

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
