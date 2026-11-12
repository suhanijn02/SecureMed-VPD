"""Seed the demo database: roles, users, VPD policies, column policies, 60 patients."""
import random
import sqlite3
from datetime import datetime

from werkzeug.security import generate_password_hash

# name: (description, insert, update, delete, policy_admin)
ROLES = {
    "ADMIN":        ("Security administrator: manages VPD policies, sees all rows but clinical data is masked or hidden", 0, 0, 1, 1),
    "DOCTOR":       ("Treating physician: full detail, but only for their own patients",                               1, 1, 0, 0),
    "NURSE":        ("Ward nurse: only patients in their own ward, national ID masked",                               0, 1, 0, 0),
    "RECEPTIONIST": ("Front desk: registers patients, never sees diagnoses or VIP patients",                          1, 0, 0, 0),
    "INTERN":       ("Trainee: no policy rows yet, shows deny-by-default",                                           0, 0, 0, 0),
}

# role -> (row predicate, {column: action})
POLICIES = {
    "ADMIN":        ("ALL_ROWS",     {"aadhaar": "MASK", "diagnosis": "HIDE", "phone": "MASK", "dob": "MASK"}),
    "DOCTOR":       ("OWN_PATIENTS", {"aadhaar": "SHOW", "diagnosis": "SHOW", "phone": "SHOW", "dob": "SHOW"}),
    "NURSE":        ("OWN_WARD",     {"aadhaar": "MASK", "diagnosis": "SHOW", "phone": "SHOW", "dob": "SHOW"}),
    "RECEPTIONIST": ("NON_VIP",      {"aadhaar": "MASK", "diagnosis": "HIDE", "phone": "SHOW", "dob": "MASK"}),
    "INTERN":       ("NO_ROWS",      {"aadhaar": "HIDE", "diagnosis": "HIDE", "phone": "HIDE", "dob": "HIDE"}),
}

USERS = [
    # username, full name, password, role, ward
    ("admin",       "Kavya Raman",      "Admin@123",     "ADMIN",        None),
    ("dr.mehta",    "Dr. Arjun Mehta",  "Doctor@123",    "DOCTOR",       "Cardiology"),
    ("dr.iyer",     "Dr. Lakshmi Iyer", "Doctor@123",    "DOCTOR",       "Neurology"),
    ("dr.khan",     "Dr. Imran Khan",   "Doctor@123",    "DOCTOR",       "Orthopaedics"),
    ("nurse.anita", "Anita Joseph",     "Nurse@123",     "NURSE",        "Cardiology"),
    ("nurse.ravi",  "Ravi Shankar",     "Nurse@123",     "NURSE",        "Neurology"),
    ("reception",   "Priya Nair",       "Reception@123", "RECEPTIONIST", None),
    ("intern",      "Rahul Verma",      "Intern@123",    "INTERN",       "General"),
]

FIRST = ["Aarav", "Vihaan", "Aditya", "Sai", "Arnav", "Rohan", "Karthik", "Vikram", "Rahul", "Siddharth",
         "Ananya", "Diya", "Isha", "Meera", "Saanvi", "Priya", "Divya", "Lakshmi", "Pooja", "Nandini",
         "Farhan", "Joseph", "Gurpreet", "Deepa", "Harini", "Manoj", "Sneha", "Tarun", "Varun", "Yamini"]
LAST = ["Sharma", "Iyer", "Reddy", "Nair", "Pillai", "Gupta", "Krishnan", "Das", "Patel", "Rao",
        "Menon", "Subramanian", "Fernandes", "Singh", "Chopra", "Banerjee", "Mukherjee", "Varma"]
PINCODES = ["600017", "600020", "600028", "600040", "600042", "603203", "603202"]
DIAGNOSES = {
    "Cardiology":   ["Hypertension", "Coronary Artery Disease", "Arrhythmia", "Heart Failure"],
    "Neurology":    ["Migraine", "Epilepsy", "Parkinson's Disease", "Ischemic Stroke"],
    "Orthopaedics": ["Femur Fracture", "Osteoarthritis", "ACL Tear", "Lumbar Disc Herniation"],
    "General":      ["Type 2 Diabetes", "Asthma", "Tuberculosis", "Dengue Fever"],
}
WARD_DOCTOR = {"Cardiology": "dr.mehta", "Neurology": "dr.iyer", "Orthopaedics": "dr.khan"}


def seed(path: str):
    rng = random.Random(361)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    for name, (desc, ins, upd, dele, adm) in ROLES.items():
        cur.execute("""INSERT INTO roles (name, description, can_insert, can_update, can_delete, is_policy_admin)
                       VALUES (?,?,?,?,?,?)""", (name, desc, ins, upd, dele, adm))
    role_id = {r["name"]: r["id"] for r in cur.execute("SELECT id, name FROM roles")}

    for uname, fname, pw, role, ward in USERS:
        cur.execute("INSERT INTO users (username, full_name, password_hash, role_id, ward) VALUES (?,?,?,?,?)",
                    (uname, fname, generate_password_hash(pw), role_id[role], ward))
    user_id = {r["username"]: r["id"] for r in cur.execute("SELECT id, username FROM users")}

    for role, (pred, cols) in POLICIES.items():
        cur.execute("""INSERT INTO vpd_policies (name, table_name, role_id, predicate_type, enabled, updated_at, updated_by)
                       VALUES (?, 'patients', ?, ?, 1, ?, 'SYSTEM')""",
                    (f"PATIENTS_{role}_POLICY", role_id[role], pred, ts))
        for col, act in cols.items():
            cur.execute("INSERT INTO column_policies (role_id, column_name, action) VALUES (?,?,?)",
                        (role_id[role], col, act))

    wards = ["Cardiology"] * 18 + ["Neurology"] * 16 + ["Orthopaedics"] * 14 + ["General"] * 12
    for i, ward in enumerate(wards, start=1):
        d = f"{rng.randint(2, 9)}{rng.randint(0, 10**11 - 1):011d}"
        doc = WARD_DOCTOR.get(ward) or rng.choice(list(WARD_DOCTOR.values()))
        cur.execute("""INSERT INTO patients (mrn, full_name, dob, gender, pincode, phone, ward, doctor_id, is_vip,
                       aadhaar, diagnosis, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (f"MRN{2026000 + i}", f"{rng.choice(FIRST)} {rng.choice(LAST)}",
                     f"{rng.randint(1950, 2004):04d}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}",
                     rng.choice("MF"), rng.choice(PINCODES), f"9{rng.randint(100000000, 999999999)}",
                     ward, user_id[doc], 1 if i % 9 == 0 else 0,
                     f"{d[:4]}-{d[4:8]}-{d[8:]}", rng.choice(DIAGNOSES[ward]), ts, ts))
    conn.commit()
    conn.close()
