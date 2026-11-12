"""
Virtual Private Database (VPD): row- and column-level security
================================================================
Topic: Unit 3, "Implementation of VPD using Views, Application Context,
Implementing VPD, Viewing VPD Policies, Implementing Row and Column level Security".

How it works (all enforced INSIDE the database, not in Python if-statements):

1. APPLICATION CONTEXT   `app_context` is a TEMP table, so it is private to each
   database session/connection, just like Oracle's SYS_CONTEXT / DBMS_SESSION.SET_CONTEXT.
   After login the application writes user_id, role and ward into it.

2. POLICY TABLES         `vpd_policies` (row predicate per role) and
   `column_policies` (SHOW / MASK / HIDE per role and column) are the data dictionary,
   comparable to DBA_POLICIES and DBA_SEC_RELEVANT_COLS.

3. SECURE VIEW           `vpd_patients` joins patients with the context and the
   policies. Its WHERE clause is the policy predicate, and its SELECT list masks or
   hides columns. The application only ever queries this view.

4. INSTEAD OF TRIGGERS   UPDATE / INSERT / DELETE on the view are routed through
   triggers that (a) can only touch rows the view exposes, (b) reject writes that would
   move a row outside the user's policy (like Oracle's update_check => TRUE), and
   (c) silently ignore writes to columns the user cannot SHOW.

5. AUTHORIZER            The SQLite authorizer callback blocks every direct read of the
   base table `patients`. It may only be reached *through* the vpd_patients view, so
   even hand-written SQL cannot bypass the policy (see the SQL console).
"""
import re
import sqlite3

# predicate_type -> (SQL template using {a} for the row alias, description)
PREDICATES = {
    "ALL_ROWS":     ("1 = 1",                       "Every row (no restriction)"),
    "OWN_PATIENTS": ("{a}.doctor_id = ctx.user_id", "Only patients assigned to the logged-in doctor"),
    "OWN_WARD":     ("{a}.ward = ctx.ward",         "Only patients in the user's own ward"),
    "NON_VIP":      ("{a}.is_vip = 0",              "Every row except VIP patients"),
    "NO_ROWS":      ("1 = 0",                       "No rows at all"),
}

# protected column -> (masking SQL expression on p.<col>, example of a masked value, description)
COLUMNS = {
    "aadhaar":   ("'XXXX-XXXX-' || substr(p.aadhaar, -4)",       "XXXX-XXXX-4821",   "Aadhaar number (national ID)"),
    "diagnosis": ("substr(p.diagnosis, 1, 1) || '******'",       "H******",          "Medical diagnosis"),
    "phone":     ("'******' || substr(p.phone, -4)",             "******3210",       "Mobile number"),
    "dob":       ("substr(p.dob, 1, 4) || '-**-**'",             "1987-**-**",       "Date of birth"),
}

PUBLIC_COLUMNS = ["id", "mrn", "full_name", "gender", "pincode", "ward", "doctor_id", "is_vip",
                  "created_at", "updated_at"]


# --------------------------------------------------------------------------- #
#                         SQL generators (the "policy function")              #
# --------------------------------------------------------------------------- #
def predicate_sql(alias: str) -> str:
    """Row predicate evaluated against the session's application context.
    No enabled policy for the role -> EXISTS is false -> no rows (deny by default)."""
    cases = " OR ".join(
        f"(v.predicate_type = '{k}' AND {tmpl.format(a=alias)})" for k, (tmpl, _) in PREDICATES.items())
    return (f"EXISTS (SELECT 1 FROM main.vpd_policies v, temp.app_context ctx "
            f"WHERE ctx.id = 1 AND v.role_id = ctx.role_id AND v.table_name = 'patients' "
            f"AND v.enabled = 1 AND ({cases}))")


def column_action_sql(col: str) -> str:
    return (f"(SELECT cp.action FROM main.column_policies cp, temp.app_context ctx "
            f"WHERE ctx.id = 1 AND cp.role_id = ctx.role_id AND cp.column_name = '{col}')")


def view_ddl() -> str:
    cols = ",\n       ".join(f"p.{c}" for c in PUBLIC_COLUMNS)
    masked = ",\n       ".join(
        f"CASE {column_action_sql(c)}\n            WHEN 'SHOW' THEN p.{c}\n            WHEN 'MASK' THEN {expr}\n"
        f"            ELSE NULL END AS {c}"            # HIDE or no policy -> NULL
        for c, (expr, _, _) in COLUMNS.items())
    return (f"CREATE TEMP VIEW vpd_patients AS\n"
            f"SELECT {cols},\n       {masked}\n"
            f"  FROM main.patients p\n WHERE {predicate_sql('p')}")


def trigger_ddls() -> list[str]:
    shown = lambda c: f"{column_action_sql(c)} = 'SHOW'"
    upd_cols = ",\n         ".join(
        [f"{c} = NEW.{c}" for c in ("full_name", "gender", "pincode", "ward", "doctor_id", "is_vip")]
        + [f"{c} = CASE WHEN {shown(c)} THEN NEW.{c} ELSE {c} END" for c in COLUMNS]
        + ["updated_at = datetime('now', 'localtime')"])
    return [
        # UPDATE: only reachable for rows visible through the view; row must stay visible afterwards
        f"""CREATE TEMP TRIGGER vpd_patients_update INSTEAD OF UPDATE ON vpd_patients
BEGIN
  SELECT RAISE(ABORT, 'VPD update_check: the new values would move this row outside your policy')
   WHERE NOT {predicate_sql('NEW')};
  UPDATE patients SET
         {upd_cols}
   WHERE id = OLD.id;
END""",
        # INSERT: new row must satisfy the inserting user's policy
        f"""CREATE TEMP TRIGGER vpd_patients_insert INSTEAD OF INSERT ON vpd_patients
BEGIN
  SELECT RAISE(ABORT, 'VPD insert check: you cannot create a row you would not be allowed to see')
   WHERE NOT {predicate_sql('NEW')};
  INSERT INTO patients (mrn, full_name, dob, gender, pincode, phone, ward, doctor_id, is_vip,
                             aadhaar, diagnosis, created_at, updated_at)
  VALUES (NEW.mrn, NEW.full_name, NEW.dob, NEW.gender, NEW.pincode, NEW.phone, NEW.ward, NEW.doctor_id,
          NEW.is_vip, NEW.aadhaar, NEW.diagnosis, datetime('now','localtime'), datetime('now','localtime'));
END""",
        # DELETE: only rows visible through the view can be deleted
        """CREATE TEMP TRIGGER vpd_patients_delete INSTEAD OF DELETE ON vpd_patients
BEGIN
  DELETE FROM patients WHERE id = OLD.id;
END""",
    ]


CONTEXT_DDL = """CREATE TEMP TABLE IF NOT EXISTS app_context (
    id        INTEGER PRIMARY KEY CHECK (id = 1),
    user_id   INTEGER,
    username  TEXT,
    role_id   INTEGER,
    role_name TEXT,
    ward      TEXT,
    set_at    TEXT
)"""


def install_session_objects(conn: sqlite3.Connection):
    """Run once per DB session: create the private context table, secure view and triggers."""
    conn.execute(CONTEXT_DDL)
    conn.execute(view_ddl())
    for ddl in trigger_ddls():
        conn.execute(ddl)


# --------------------------------------------------------------------------- #
#                         Application context API                             #
# --------------------------------------------------------------------------- #
def set_context(conn, user):
    """Equivalent of DBMS_SESSION.SET_CONTEXT('patient_ctx', 'user_id', ...)."""
    conn.execute("DELETE FROM temp.app_context")
    conn.execute("""INSERT INTO temp.app_context (id, user_id, username, role_id, role_name, ward, set_at)
                    VALUES (1, ?, ?, ?, ?, ?, datetime('now','localtime'))""",
                 (user["id"], user["username"], user["role_id"], user["role_name"], user["ward"]))


def clear_context(conn):
    conn.execute("DELETE FROM temp.app_context")


def get_context(conn):
    return conn.execute("SELECT * FROM temp.app_context WHERE id = 1").fetchone()


# --------------------------------------------------------------------------- #
#                 Human-readable explanation of what is enforced              #
# --------------------------------------------------------------------------- #
def explain(conn, role_id, user=None):
    """Return the effective policy for a role, with the predicate made concrete."""
    pol = conn.execute("""SELECT * FROM vpd_policies WHERE role_id = ? AND table_name = 'patients'""",
                       (role_id,)).fetchone()
    if pol is None or not pol["enabled"]:
        ptype, name = "NO_ROWS", (pol["name"] + " (DISABLED)") if pol else "none - default deny"
    else:
        ptype, name = pol["predicate_type"], pol["name"]
    pred = PREDICATES[ptype][0].format(a="p")
    if user is not None:
        pred = pred.replace("ctx.user_id", str(user["id"])).replace("ctx.ward", repr(user["ward"]))
    cols = {c: "HIDE" for c in COLUMNS}
    for r in conn.execute("SELECT column_name, action FROM column_policies WHERE role_id = ?", (role_id,)):
        cols[r["column_name"]] = r["action"]
    return {"policy": name, "type": ptype, "predicate": pred, "columns": cols,
            "rewritten": f"SELECT * FROM patients p WHERE {pred}"}


# --------------------------------------------------------------------------- #
#        SQL console: authorizer that makes the base table unreachable        #
# --------------------------------------------------------------------------- #
ALLOWED_DIRECT = {"vpd_patients", "app_context"}


def console_authorizer(action, arg1, arg2, dbname, source):
    """sqlite3 authorizer. `source` is the inner-most view/trigger the access comes from.
    Base tables may only be read when the read originates inside the vpd_patients view."""
    if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE):
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_READ:
        if arg1 in ALLOWED_DIRECT or source == "vpd_patients":
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_DENY                 # no INSERT/UPDATE/DELETE/DDL/PRAGMA/ATTACH


def run_console(conn, sql: str, max_rows=200):
    sql = sql.strip().rstrip(";").strip()
    if not re.match(r"(?is)^(select|with)\b", sql):
        raise ValueError("Only a single SELECT statement is allowed in the console.")
    if ";" in sql:
        raise ValueError("Only one statement at a time.")
    steps = {"n": 0}

    def guard():                                # abort runaway queries
        steps["n"] += 1
        return 1 if steps["n"] > 2000 else 0

    conn.set_authorizer(console_authorizer)
    conn.set_progress_handler(guard, 1000)
    try:
        cur = conn.execute(sql)
        cols = [d[0] for d in cur.description or []]
        rows = cur.fetchmany(max_rows)
        return cols, [tuple(r) for r in rows]
    finally:
        conn.set_authorizer(None)
        conn.set_progress_handler(None, 0)
