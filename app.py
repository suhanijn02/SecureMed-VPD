"""
SecureMed VPD - Row & Column Level Security using a Virtual Private Database
Course 21CSE361T Database Security & Privacy - Unit 3 (Database Application Security Models)

Run:    python app.py              -> http://127.0.0.1:5000  (creates + seeds the DB on first run)
Reset:  python app.py --reset
"""
import os
import re
import secrets
import sqlite3
import sys
from datetime import datetime

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

import database
from database import get_db
from security import vpd

BASE = os.path.dirname(os.path.abspath(__file__))
INSTANCE = os.path.join(BASE, "instance")
WARDS = ["Cardiology", "Neurology", "Orthopaedics", "General"]

app = Flask(__name__)
app.config.update(DATABASE=os.path.join(INSTANCE, "securemed.db"),
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")
app.teardown_appcontext(database.close_db)


def _secret_key():
    os.makedirs(INSTANCE, exist_ok=True)
    path = os.path.join(INSTANCE, "secret.key")
    if not os.path.exists(path):
        with open(path, "w") as fh:
            fh.write(secrets.token_hex(32))
    with open(path) as fh:
        return fh.read().strip()


app.secret_key = _secret_key()


def bootstrap(reset=False):
    db_path = app.config["DATABASE"]
    if reset and os.path.exists(db_path):
        os.remove(db_path)
    fresh = not os.path.exists(db_path)
    database.init_schema(db_path)
    if fresh:
        from seed import seed
        seed(db_path)
        print(" * Database created and seeded:", db_path)


# ======================================================================= #
#           Request pipeline: user -> application context, CSRF           #
# ======================================================================= #
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


@app.context_processor
def inject():
    return {"csrf": lambda: Markup(f'<input type="hidden" name="csrf_token" value="{csrf_token()}">'),
            "current_user": g.get("user"), "WARDS": WARDS}


def load_user(db, user_id):
    return db.execute("""SELECT u.*, r.name AS role_name, r.can_insert, r.can_update, r.can_delete,
                                r.is_policy_admin
                           FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = ?""", (user_id,)).fetchone()


@app.before_request
def before():
    g.user = None
    if request.endpoint == "static":
        return
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, description="Invalid or missing CSRF token. Reload the page and try again.")
    if session.get("user_id"):
        db = get_db()
        g.user = load_user(db, session["user_id"])
        if g.user is None:
            session.clear()
            return redirect(url_for("login"))
        # ---- the heart of VPD: bind this DB session to the user ----
        vpd.set_context(db, g.user)


@app.after_request
def headers(resp):
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                                               "img-src 'self' data:; frame-ancestors 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
def http_error(e):
    return render_template("error.html", code=e.code, message=e.description), e.code


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*a, **kw):
        if g.user is None:
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapped


def require(flag, label):
    """Statement-type permission (which DML the role may run at all)."""
    if not g.user[flag]:
        abort(403, description=f"Your role ({g.user['role_name']}) is not permitted to {label}.")


# ======================================================================= #
#                               Login                                    #
# ======================================================================= #
DUMMY_HASH = generate_password_hash("timing-equaliser")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        db = get_db()
        row = db.execute("SELECT id, password_hash FROM users WHERE username = ?",
                         (request.form.get("username", "").strip(),)).fetchone()
        ok = check_password_hash(row["password_hash"] if row else DUMMY_HASH, request.form.get("password", ""))
        if row and ok:
            session.clear()                                  # new session id: prevents fixation
            session["user_id"] = row["id"]
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("dashboard"))
        flash("Invalid username or password.", "error")
        return render_template("login.html"), 401
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Signed out. Your application context was cleared.", "info")
    return redirect(url_for("login"))


# ======================================================================= #
#                              Dashboard                                 #
# ======================================================================= #
@app.route("/")
@login_required
def dashboard():
    db = get_db()
    ctx = vpd.get_context(db)
    info = vpd.explain(db, g.user["role_id"], g.user)
    visible = db.execute("SELECT COUNT(*) FROM vpd_patients").fetchone()[0]
    total = db.execute("SELECT COUNT(*) FROM patients").fetchone()[0]   # app-level stat only
    by_ward = db.execute("SELECT ward, COUNT(*) c FROM vpd_patients GROUP BY ward ORDER BY c DESC").fetchall()
    return render_template("dashboard.html", ctx=ctx, info=info, visible=visible, total=total, by_ward=by_ward,
                           columns=vpd.COLUMNS)


# ======================================================================= #
#               Patients - every query goes through vpd_patients          #
# ======================================================================= #
def _doctors(db):
    return db.execute("""SELECT u.id, u.full_name, u.ward FROM users u JOIN roles r ON r.id = u.role_id
                         WHERE r.name = 'DOCTOR' ORDER BY u.full_name""").fetchall()


@app.route("/patients")
@login_required
def patients():
    db = get_db()
    q, ward = request.args.get("q", "").strip(), request.args.get("ward", "")
    sql = """SELECT v.*, d.full_name AS doctor_name FROM vpd_patients v
             LEFT JOIN users d ON d.id = v.doctor_id WHERE 1 = 1"""
    params = []
    if q:
        sql += " AND (v.full_name LIKE ? OR v.mrn LIKE ?)"
        params += [f"%{q}%"] * 2
    if ward in WARDS:
        sql += " AND v.ward = ?"
        params.append(ward)
    rows = db.execute(sql + " ORDER BY v.id", params).fetchall()
    info = vpd.explain(db, g.user["role_id"], g.user)
    return render_template("patients.html", rows=rows, info=info, q=q, ward=ward)


def _visible(db, pid):
    return db.execute("""SELECT v.*, d.full_name AS doctor_name FROM vpd_patients v
                         LEFT JOIN users d ON d.id = v.doctor_id WHERE v.id = ?""", (pid,)).fetchone()


@app.route("/patients/<int:pid>")
@login_required
def patient_view(pid):
    db = get_db()
    p = _visible(db, pid)
    if p is None:
        abort(404, description=f"Patient #{pid} is not visible to you. To your role it does not exist. "
                               "Row-level security returns 'not found', not 'forbidden', so it leaks nothing.")
    return render_template("patient_view.html", p=p, info=vpd.explain(db, g.user["role_id"], g.user))


def _validate(form, cols, creating):
    errors, d = [], {}
    d["full_name"] = form.get("full_name", "").strip()
    if not re.fullmatch(r"[A-Za-z .'-]{2,80}", d["full_name"]):
        errors.append("Name must be 2-80 letters.")
    d["gender"] = form.get("gender", "")
    if d["gender"] not in ("M", "F", "O"):
        errors.append("Invalid gender.")
    d["pincode"] = form.get("pincode", "").strip()
    if not re.fullmatch(r"[1-9]\d{5}", d["pincode"]):
        errors.append("PIN code must be 6 digits.")
    d["ward"] = form.get("ward", "")
    if d["ward"] not in WARDS:
        errors.append("Invalid ward.")
    d["is_vip"] = 1 if form.get("is_vip") else 0
    # protected columns: writable on INSERT, or on UPDATE only when the policy is SHOW
    for col in vpd.COLUMNS:
        d[col] = None
        if not (creating or cols[col] == "SHOW"):
            continue
        if col == "diagnosis" and cols[col] != "SHOW":
            continue
        val = form.get(col, "").strip()
        if col == "dob":
            try:
                if datetime.strptime(val, "%Y-%m-%d") > datetime.now():
                    errors.append("Date of birth cannot be in the future.")
            except ValueError:
                errors.append("Invalid date of birth.")
        elif col == "phone" and not re.fullmatch(r"[6-9]\d{9}", val):
            errors.append("Phone must be a 10-digit mobile number.")
        elif col == "aadhaar":
            a = re.sub(r"[\s-]", "", val)
            if not re.fullmatch(r"[2-9]\d{11}", a):
                errors.append("Aadhaar must be 12 digits.")
            val = f"{a[:4]}-{a[4:8]}-{a[8:]}"
        d[col] = val[:120] or None
    return errors, d


@app.route("/patients/new", methods=["GET", "POST"])
@login_required
def patient_new():
    require("can_insert", "INSERT patients")
    db = get_db()
    info = vpd.explain(db, g.user["role_id"], g.user)
    if request.method == "POST":
        errors, d = _validate(request.form, info["columns"], creating=True)
        doctor_id = g.user["id"] if g.user["role_name"] == "DOCTOR" else request.form.get("doctor_id", type=int)
        if doctor_id not in {r["id"] for r in _doctors(db)}:
            errors.append("Select a valid doctor.")
        if not errors:
            mrn = f"MRN{2026000 + db.execute('SELECT COALESCE(MAX(id),0)+1 FROM patients').fetchone()[0]}"
            try:
                db.execute("""INSERT INTO vpd_patients (mrn, full_name, dob, gender, pincode, phone, ward, doctor_id,
                              is_vip, aadhaar, diagnosis) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                           (mrn, d["full_name"], d["dob"], d["gender"], d["pincode"], d["phone"], d["ward"],
                            doctor_id, d["is_vip"], d["aadhaar"], d["diagnosis"]))
                db.commit()
                flash(f"{mrn} registered through the vpd_patients view.", "success")
                return redirect(url_for("patients"))
            except sqlite3.DatabaseError as e:
                db.rollback()
                errors.append(f"Blocked by the database: {e}")
        for e in errors:
            flash(e, "error")
        return render_template("patient_form.html", p=request.form, cols=info["columns"], doctors=_doctors(db), creating=True)
    return render_template("patient_form.html", p={}, cols=info["columns"], doctors=_doctors(db), creating=True)


@app.route("/patients/<int:pid>/edit", methods=["GET", "POST"])
@login_required
def patient_edit(pid):
    require("can_update", "UPDATE patients")
    db = get_db()
    p = _visible(db, pid)
    if p is None:
        abort(404, description="Not visible under your row-level policy, so it cannot be updated.")
    info = vpd.explain(db, g.user["role_id"], g.user)
    if request.method == "POST":
        errors, d = _validate(request.form, info["columns"], creating=False)
        if not errors:
            try:
                db.execute("""UPDATE vpd_patients SET full_name=?, gender=?, pincode=?, ward=?, is_vip=?,
                              dob=?, phone=?, aadhaar=?, diagnosis=? WHERE id=?""",
                           (d["full_name"], d["gender"], d["pincode"], d["ward"], d["is_vip"],
                            d["dob"], d["phone"], d["aadhaar"], d["diagnosis"], pid))
                db.commit()
                flash("Record updated. Columns your policy does not SHOW were left untouched by the trigger.", "success")
                if _visible(db, pid):
                    return redirect(url_for("patient_view", pid=pid))
                return redirect(url_for("patients"))
            except sqlite3.DatabaseError as e:
                db.rollback()
                errors.append(f"Blocked by the database: {e}")
        for e in errors:
            flash(e, "error")
        return render_template("patient_form.html", p={**dict(p), **request.form.to_dict()}, cols=info["columns"], creating=False)
    return render_template("patient_form.html", p=p, cols=info["columns"], creating=False)


@app.route("/patients/<int:pid>/delete", methods=["POST"])
@login_required
def patient_delete(pid):
    require("can_delete", "DELETE patients")
    db = get_db()
    p = _visible(db, pid)              # INSTEAD OF triggers always report rowcount 0, so check first
    if p is None:
        abort(404, description="Not visible under your row-level policy, so it cannot be deleted.")
    db.execute("DELETE FROM vpd_patients WHERE id = ?", (pid,))
    db.commit()
    flash(f"{p['mrn']} deleted through the vpd_patients view.", "success")
    return redirect(url_for("patients"))


# ======================================================================= #
#               Viewing & managing VPD policies (data dictionary)         #
# ======================================================================= #
@app.route("/policies", methods=["GET", "POST"])
@login_required
def policies():
    db = get_db()
    if request.method == "POST":
        if not g.user["is_policy_admin"]:
            abort(403, description="Only a policy administrator can change VPD policies.")
        f = request.form
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if f.get("op") == "row":
            ptype = f.get("predicate_type")
            if ptype not in vpd.PREDICATES:
                abort(400)
            db.execute("UPDATE vpd_policies SET predicate_type=?, enabled=?, updated_at=?, updated_by=? WHERE id=?",
                       (ptype, 1 if f.get("enabled") else 0, stamp, g.user["username"], f.get("id", type=int)))
            flash("Row policy updated. It applies to the next query of every user with that role.", "success")
        elif f.get("op") == "column":
            act = f.get("action")
            if act not in ("SHOW", "MASK", "HIDE"):
                abort(400)
            db.execute("UPDATE column_policies SET action=? WHERE id=?", (act, f.get("id", type=int)))
            flash("Column policy updated.", "success")
        db.commit()
        return redirect(url_for("policies") + "#" + f.get("op", ""))

    rows = db.execute("""SELECT v.*, r.name AS role_name, r.description,
                                (SELECT COUNT(*) FROM users u WHERE u.role_id = r.id) AS members
                           FROM roles r LEFT JOIN vpd_policies v ON v.role_id = r.id ORDER BY r.id""").fetchall()
    colpol = {}
    for c in db.execute("""SELECT c.*, r.name AS role_name FROM column_policies c JOIN roles r ON r.id = c.role_id
                           ORDER BY r.id"""):
        colpol.setdefault(c["role_name"], {})[c["column_name"]] = c
    ddl = db.execute("""SELECT type, name, sql FROM sqlite_temp_master
                        WHERE name IN ('vpd_patients','vpd_patients_update','vpd_patients_insert','vpd_patients_delete',
                                       'app_context') ORDER BY type DESC, name""").fetchall()
    return render_template("policies.html", rows=rows, colpol=colpol, predicates=vpd.PREDICATES,
                           columns=vpd.COLUMNS, ddl=ddl)


# ======================================================================= #
#          Policy simulator: what does every user see, side by side?       #
# ======================================================================= #
@app.route("/simulator")
@login_required
def simulator():
    if not g.user["is_policy_admin"]:
        abort(403, description="Only a policy administrator can impersonate other contexts.")
    db = get_db()
    users = db.execute("SELECT id FROM users ORDER BY id").fetchall()
    selected = request.args.get("user", type=int) or users[0]["id"]
    results, preview = [], None
    sim = database.connect(app.config["DATABASE"])          # a separate DB session
    try:
        for u in users:
            user = load_user(db, u["id"])
            vpd.set_context(sim, user)
            count = sim.execute("SELECT COUNT(*) FROM vpd_patients").fetchone()[0]
            results.append({"user": user, "count": count, "info": vpd.explain(db, user["role_id"], user)})
            if user["id"] == selected:
                preview = {"user": user, "rows": sim.execute("SELECT * FROM vpd_patients ORDER BY id LIMIT 12").fetchall()}
    finally:
        sim.close()
    total = db.execute("SELECT COUNT(*) FROM patients").fetchone()[0]
    return render_template("simulator.html", results=results, preview=preview, selected=selected, total=total,
                           columns=vpd.COLUMNS)


# ======================================================================= #
#           SQL console: prove the policy cannot be bypassed with SQL     #
# ======================================================================= #
EXAMPLES = [
    ("Query the secure view", "SELECT mrn, full_name, ward, aadhaar, diagnosis FROM vpd_patients"),
    ("Read my application context", "SELECT * FROM app_context"),
    ("Try to bypass: read the base table", "SELECT * FROM patients"),
    ("Try SQL injection", "SELECT * FROM vpd_patients WHERE 1=1 OR 1=1"),
    ("Try to read the users table", "SELECT username, password_hash FROM users"),
    ("Aggregate through the view", "SELECT ward, COUNT(*) AS n FROM vpd_patients GROUP BY ward"),
]


@app.route("/console", methods=["GET", "POST"])
@login_required
def console():
    sql = request.form.get("sql", EXAMPLES[0][1]) if request.method == "POST" else request.args.get("sql", EXAMPLES[0][1])
    result = error = None
    if request.method == "POST":
        try:
            cols, rows = vpd.run_console(get_db(), sql[:2000])
            result = {"cols": cols, "rows": rows}
        except (sqlite3.DatabaseError, ValueError) as e:
            msg = str(e)
            if "not authorized" in msg or "prohibited" in msg:
                msg += ". The authorizer only lets the base table be read through the vpd_patients view."
            error = msg
    return render_template("console.html", sql=sql, result=result, error=error, examples=EXAMPLES)


# ======================================================================= #
bootstrap(reset="--reset" in sys.argv)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f" * SecureMed VPD running on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)
