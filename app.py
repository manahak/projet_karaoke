from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort, Response
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from pymongo import MongoClient
from bson import ObjectId, json_util
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
            # 'nom' is the display name for a box; fall back to legacy 'type' or to 'Mixte'
            "nom": b.get("nom") or b.get("type") or 'Mixte',
            # optional image field (can be URL or data URL)
            "image": b.get("image") or None,
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
        'nom': box.get('nom') or box.get('type') or 'Mixte',
        'image': box.get('image') or None,
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


@app.route('/admin')
def admin():
    # Admin placeholder page — only for admin users
    if 'user' not in session:
        return redirect(url_for('login'))
    user = session.get('user')
    if user.get('role') != 'admin':
        # forbidden
        abort(403)
    # provide a small server-side sample of users for quick debug display
    try:
        sample_cursor = users.find().limit(10)
        sample = []
        for d in sample_cursor:
            doc = {}
            for k, v in d.items():
                if k == '_id':
                    doc[k] = str(v)
                else:
                    try:
                        doc[k] = v
                    except Exception:
                        doc[k] = str(v)
            sample.append(doc)
    except Exception:
        sample = []
    # list available static images for boxes (to show as selectable placeholders in admin)
    import os
    img_dir = os.path.join(os.path.dirname(__file__), 'static', 'img')
    imgs = []
    try:
        for fname in os.listdir(img_dir):
            # consider common web image extensions and files that include 'box' or 'hero'
            if fname.lower().endswith(('.png', '.jpg', '.jpeg', '.svg', '.webp')):
                imgs.append(fname)
    except Exception:
        imgs = []
    return render_template('admin.html', server_docs=sample, static_box_images=imgs)


def _admin_require():
    if 'user' not in session:
        return False
    return session.get('user', {}).get('role') == 'admin'


def _get_collection(name):
    # whitelist collections
    if name == 'users':
        return users
    if name == 'box' or name == 'boxes':
        return db.box
    if name == 'reservation' or name == 'reservations':
        return db.reservation
    if name == 'admin_logs' or name == 'logs':
        return db.admin_logs
    return None


def _log_admin_action(admin_user_id, action, col, doc_id=None, details=None):
    try:
        db.admin_logs.insert_one({
            'admin_id': ObjectId(admin_user_id) if admin_user_id else None,
            'action': action,
            'collection': col,
            'doc_id': str(doc_id) if doc_id else None,
            'details': details,
            'created_at': datetime.utcnow()
        })
    except Exception:
        # logging must not break main flow
        pass


@app.route('/admin/api/list')
def admin_api_list():
    if not _admin_require():
        return jsonify({'error': 'forbidden'}), 403
    col = request.args.get('col')
    q = request.args.get('q')
    sort = request.args.get('sort')
    coll = _get_collection(col)
    if coll is None:
        return jsonify({'error': 'invalid_collection'}), 400
    # build filter for simple search
    filt = {}
    if q:
        # simple heuristics per collection
        if col == 'users':
            filt = {'$or': [{'username': {'$regex': q, '$options': 'i'}}, {'email': {'$regex': q, '$options': 'i'}}]}
        elif col in ('box', 'boxes'):
            # search by box number or name ('nom') — older data might still have 'type'
            filt = {'$or': [
                {'numero': {'$regex': q, '$options': 'i'}},
                {'nom': {'$regex': q, '$options': 'i'}},
                {'type': {'$regex': q, '$options': 'i'}}
            ]}
        elif col in ('reservation', 'reservations'):
            filt = {'$or': [{'date': {'$regex': q, '$options': 'i'}}, {'notes': {'$regex': q, '$options': 'i'}}]}
        elif col == 'admin_logs':
            filt = {'$or': [{'action': {'$regex': q, '$options': 'i'}}, {'collection': {'$regex': q, '$options': 'i'}}]}

    # prepare sort mapping (support logical values 'id','alpha','modified')
    sort_spec = None
    if sort:
        # map logical sort keys to actual document keys per collection
        key = sort
        direction = 1
        if sort.startswith('-'):
            direction = -1
            key = sort[1:]
        # logical keys
        if key in ('id', '_id'):
            real_key = '_id'
        elif key == 'alpha':
            if col == 'users':
                real_key = 'username'
            elif col in ('box', 'boxes'):
                real_key = 'numero'
            else:
                real_key = 'date'
        elif key == 'modified':
            # try updated_at then created_at
            real_key = 'updated_at'
            # note: we'll attempt to sort by updated_at; if not present we'll fallback to created_at
        else:
            real_key = key
        sort_spec = (real_key, direction)

    docs = []
    cursor = coll.find(filt)
    if sort_spec:
        try:
            cursor = cursor.sort([sort_spec])
        except Exception:
            # fallback: if we tried 'updated_at', try 'created_at'
            try:
                if sort_spec[0] == 'updated_at':
                    cursor = cursor.sort([('created_at', sort_spec[1])])
            except Exception:
                pass
    for d in cursor:
        docs.append(d)
    # Enrich reservations with readable client name and box numero for UI (visual only)
    if col in ('reservation', 'reservations'):
        try:
            for d in docs:
                # user_id may be ObjectId or string
                uid = d.get('user_id')
                client_name = None
                try:
                    if uid:
                        if isinstance(uid, str):
                            try:
                                uid_oid = ObjectId(uid)
                            except Exception:
                                uid_oid = uid
                        else:
                            uid_oid = uid
                        u = users.find_one({'_id': uid_oid}) if uid_oid else None
                        if not u:
                            u = db.clients.find_one({'_id': uid_oid}) if uid_oid else None
                        client_name = u.get('username') if u else None
                except Exception:
                    client_name = None
                d['client_name'] = client_name

                bid = d.get('box_id')
                box_numero = None
                try:
                    if bid:
                        if isinstance(bid, str):
                            try:
                                bid_oid = ObjectId(bid)
                            except Exception:
                                bid_oid = bid
                        else:
                            bid_oid = bid
                        b = db.box.find_one({'_id': bid_oid}) if bid_oid else None
                        box_numero = b.get('numero') if b else None
                except Exception:
                    box_numero = None
                d['box_numero'] = box_numero
        except Exception:
            # enrichment failure shouldn't block response
            pass
    # Use bson.json_util to serialize possible ObjectId/datetime inside docs
    try:
        return Response(json_util.dumps({'docs': docs}), mimetype='application/json')
    except Exception:
        # fallback: stringifying individual fields
        out = []
        for d in docs:
            doc = {}
            for k, v in d.items():
                if k == '_id':
                    doc[k] = str(v)
                elif isinstance(v, (str, int, float, bool)) or v is None:
                    doc[k] = v
                else:
                    doc[k] = str(v)
            out.append(doc)
        return jsonify({'docs': out})


@app.route('/admin/api/create', methods=['POST'])
def admin_api_create():
    if not _admin_require():
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(force=True)
    col = data.get('col')
    payload = data.get('doc')
    coll = _get_collection(col)
    if coll is None or not isinstance(payload, dict):
        return jsonify({'error': 'invalid_request'}), 400
    # If creating user and password provided, hash it
    if col == 'users' and 'password' in payload and payload.get('password'):
        payload['password'] = generate_password_hash(payload['password'])
    # remove _id if present
    payload.pop('_id', None)
    res = coll.insert_one(payload)
    # log admin action
    try:
        admin_id = session.get('user', {}).get('user_id')
    except Exception:
        admin_id = None
    _log_admin_action(admin_id, 'create', col, str(res.inserted_id), payload)
    return jsonify({'inserted_id': str(res.inserted_id)})


@app.route('/admin/api/update', methods=['POST'])
def admin_api_update():
    if not _admin_require():
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(force=True)
    col = data.get('col')
    doc_id = data.get('id')
    updates = data.get('doc')
    if not col or not doc_id or not isinstance(updates, dict):
        return jsonify({'error': 'invalid_request'}), 400
    coll = _get_collection(col)
    if coll is None:
        return jsonify({'error': 'invalid_collection'}), 400
    try:
        oid = ObjectId(doc_id)
    except Exception:
        return jsonify({'error': 'invalid_id'}), 400
    # special handling for users: prevent removing last admin, hash password if provided
    if col == 'users':
        # check role change: if demoting an admin, ensure at least one remains
        try:
            existing = coll.find_one({'_id': oid})
            if existing:
                old_role = existing.get('role')
                new_role = updates.get('role', old_role)
                if old_role == 'admin' and new_role != 'admin':
                    admin_count = coll.count_documents({'role': 'admin'})
                    # if this is the last admin, block the demotion
                    if admin_count <= 1:
                        return jsonify({'error': 'cannot_remove_last_admin'}), 400
        except Exception:
            pass
        if 'password' in updates and updates.get('password'):
            updates['password'] = generate_password_hash(updates['password'])

    # do update
    result = coll.update_one({'_id': oid}, {'$set': updates})
    if result.matched_count == 0:
        return jsonify({'error': 'not_found'}), 404
    # log admin action
    try:
        admin_id = session.get('user', {}).get('user_id')
    except Exception:
        admin_id = None
    _log_admin_action(admin_id, 'update', col, doc_id, updates)
    return jsonify({'updated': True})


@app.route('/admin/api/delete', methods=['POST'])
def admin_api_delete():
    if not _admin_require():
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(force=True)
    col = data.get('col')
    doc_id = data.get('id')
    if not col or not doc_id:
        return jsonify({'error': 'invalid_request'}), 400
    coll = _get_collection(col)
    if coll is None:
        return jsonify({'error': 'invalid_collection'}), 400
    try:
        oid = ObjectId(doc_id)
    except Exception:
        return jsonify({'error': 'invalid_id'}), 400
    # if deleting a user admin, ensure at least one admin remains
    if col == 'users':
        try:
            doc = coll.find_one({'_id': oid})
            if doc and doc.get('role') == 'admin':
                admin_count = coll.count_documents({'role': 'admin'})
                if admin_count <= 1:
                    return jsonify({'error': 'cannot_delete_last_admin'}), 400
        except Exception:
            pass

    res = coll.delete_one({'_id': oid})
    # log admin action
    try:
        admin_id = session.get('user', {}).get('user_id')
    except Exception:
        admin_id = None
    _log_admin_action(admin_id, 'delete', col, doc_id, None)
    return jsonify({'deleted': res.deleted_count > 0})


@app.route('/account_update', methods=['POST'])
def account_update():
    # Update current user's profile per-field: action in {'username','email','password'}
    if 'user' not in session:
        return redirect(url_for('login'))

    user_session = session.get('user')
    try:
        user_oid = ObjectId(user_session.get('user_id'))
    except Exception:
        flash('Utilisateur introuvable.', 'error')
        return redirect(url_for('dashboard'))

    action = request.form.get('action')
    # find which collection holds the user
    user_doc = users.find_one({'_id': user_oid})
    user_collection = users
    if not user_doc:
        user_doc = db.clients.find_one({'_id': user_oid})
        user_collection = db.clients

    if not user_doc:
        flash('Utilisateur introuvable.', 'error')
        return redirect(url_for('dashboard'))

    if action == 'username':
        username = request.form.get('username')
        if not username:
            flash('Nom d\'utilisateur requis.', 'error')
            return redirect(url_for('dashboard'))
        user_collection.update_one({'_id': user_oid}, {'$set': {'username': username}})
        session['user']['username'] = username
        flash('Nom d\'utilisateur mis à jour.', 'success')
        return redirect(url_for('dashboard'))

    if action == 'email':
        email = request.form.get('email')
        email_confirm = request.form.get('email_confirm')
        if not email or not email_confirm:
            flash('Veuillez renseigner et confirmer la nouvelle adresse e‑mail.', 'error')
            return redirect(url_for('dashboard'))
        if email.strip() != email_confirm.strip():
            flash('Les adresses e‑mail ne correspondent pas.', 'error')
            return redirect(url_for('dashboard'))
        user_collection.update_one({'_id': user_oid}, {'$set': {'email': email}})
        session['user']['email'] = email
        flash('Adresse e‑mail mise à jour.', 'success')
        return redirect(url_for('dashboard'))

    if action == 'password':
        current = request.form.get('current_password')
        new = request.form.get('new_password')
        new_confirm = request.form.get('new_password_confirm')
        if not current or not new or not new_confirm:
            flash('Veuillez fournir l\'ancien mot de passe et le nouveau (confirmation).', 'error')
            return redirect(url_for('dashboard'))
        if new != new_confirm:
            flash('Le nouveau mot de passe et sa confirmation ne correspondent pas.', 'error')
            return redirect(url_for('dashboard'))
        stored_pw = user_doc.get('password')
        if not stored_pw or not check_password_hash(stored_pw, current):
            flash('Mot de passe actuel incorrect.', 'error')
            return redirect(url_for('dashboard'))
        hashed = generate_password_hash(new)
        user_collection.update_one({'_id': user_oid}, {'$set': {'password': hashed}})
        flash('Mot de passe mis à jour.', 'success')
        return redirect(url_for('dashboard'))

    flash('Action non reconnue.', 'error')
    return redirect(url_for('dashboard'))

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
