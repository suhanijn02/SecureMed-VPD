# SecureMed VPD: Row and Column Level Security using a Virtual Private Database

**Course:** 21CSE361T Database Security and Privacy
**Unit 3:** Database Application Security Models
**Topic:** Implementation of VPD using Views and Application Context, Implementing VPD, Viewing VPD Policies, Implementing Row and Column Level Security

SecureMed is a hospital patient-records system. Every user queries the **same** `patients` table, and the **database itself** decides which rows and which column values each user gets back. The decision is based on who the user is: their role, their user id and their ward.

---

## 1. Problem statement

A hospital database holds sensitive data: Aadhaar numbers, diagnoses, phone numbers and dates of birth. Different staff need different slices of it:

| Role | Rows they may see | Columns |
|---|---|---|
| Doctor | Only their **own** patients | Everything |
| Nurse | Only patients in their **own ward** | Aadhaar masked |
| Receptionist | All patients **except VIPs** | Diagnosis hidden, Aadhaar and DOB masked |
| Admin (DBA) | All rows | Clinical data masked or hidden (separation of duties) |
| Intern | Nothing (deny by default) | Nothing |

If these rules are written as `if` statements in the application, one missed check leaks data. A **Virtual Private Database** instead enforces them *inside the database*, on every query.

## 2. How the VPD is implemented

```
 Login ──► APPLICATION CONTEXT ──► POLICY FUNCTION ──► SECURE VIEW ──► rows + masked columns
           (temp.app_context)      (vpd_policies,      (vpd_patients)
                                    column_policies)
```

| Concept (Oracle) | This project (SQLite) | File |
|---|---|---|
| `DBMS_SESSION.SET_CONTEXT` / `SYS_CONTEXT` | `app_context`: a **TEMP** table, private to each DB session | `security/vpd.py` → `set_context()` |
| `DBMS_RLS.ADD_POLICY` (policy function returning a predicate) | `vpd_policies` table + `predicate_sql()` generator | `security/vpd.py` |
| VPD using views | `vpd_patients` view: `WHERE <policy predicate>` | `security/vpd.py` → `view_ddl()` |
| Column-level security / column masking (`sec_relevant_cols`) | `column_policies` (SHOW / MASK / HIDE) → `CASE` expressions in the view | `security/vpd.py` |
| `update_check => TRUE`, statement types INSERT / UPDATE / DELETE | `INSTEAD OF` triggers on the view | `security/vpd.py` → `trigger_ddls()` |
| Viewing policies (`DBA_POLICIES`) | *VPD policies* page reads the dictionary tables and the live DDL from `sqlite_temp_master` | `templates/policies.html` |
| Policy cannot be bypassed | SQLite **authorizer** blocks direct reads of `patients`; it is reachable only through the view | `security/vpd.py` → `console_authorizer()` |

### Row predicate (generated policy function)
```sql
EXISTS (SELECT 1 FROM vpd_policies v, temp.app_context ctx
         WHERE v.role_id = ctx.role_id AND v.enabled = 1 AND (
               (v.predicate_type = 'ALL_ROWS')
            OR (v.predicate_type = 'OWN_PATIENTS' AND p.doctor_id = ctx.user_id)
            OR (v.predicate_type = 'OWN_WARD'     AND p.ward      = ctx.ward)
            OR (v.predicate_type = 'NON_VIP'      AND p.is_vip    = 0)))
```
If a role has no enabled policy, `EXISTS` is false and the role gets **no rows** (deny by default).

### Column policy (inside the view)
```sql
CASE (SELECT action FROM column_policies WHERE role = <ctx.role> AND column_name = 'aadhaar')
     WHEN 'SHOW' THEN p.aadhaar
     WHEN 'MASK' THEN 'XXXX-XXXX-' || substr(p.aadhaar, -4)
     ELSE NULL END AS aadhaar
```

### Write protection (INSTEAD OF triggers)
* **UPDATE / DELETE** only reach rows the view exposes. A row outside your policy cannot be changed.
* **update_check:** a nurse who moves a patient to another ward gets `RAISE(ABORT, 'VPD update_check …')`.
* **insert check:** a receptionist cannot register a VIP patient, because that is a row they would not be allowed to see.
* Columns that are not `SHOW` for your role are left unchanged, even if a value is sent.

## 3. Features (web application)

| Page | What it shows |
|---|---|
| **My security context** | Your live `app_context` row, your effective predicate, the query as rewritten, and your column rules |
| **Patients** | List, search, view, register, edit and delete patients, all through `vpd_patients` |
| **VPD policies** | Data-dictionary view of row and column policies (editable by ADMIN) plus the live DDL of the view and triggers |
| **Policy simulator** (ADMIN) | Opens a separate DB session per user and shows, side by side, how many rows and which columns each one gets |
| **SQL console** | Run your own SELECT. Try `SELECT * FROM patients`: the authorizer blocks it |

Other security measures: salted password hashes (Werkzeug), CSRF tokens on every form, session-fixation protection, parameterised SQL everywhere, Content-Security-Policy and anti-framing headers. A row outside your policy returns **404 rather than 403**, so its existence is not leaked.

## 4. Running it

Requires Python 3.10 or later.

```bash
pip install -r requirements.txt
python app.py            # open http://127.0.0.1:5000
python app.py --reset    # wipe and re-seed the demo database
```
On Windows you can also double-click **run.bat**.

### Demo accounts
| Username | Password | Role | Expected rows |
|---|---|---|---|
| admin | Admin@123 | ADMIN | 60 (masked) |
| dr.mehta | Doctor@123 | DOCTOR (Cardiology) | own patients |
| dr.iyer | Doctor@123 | DOCTOR (Neurology) | own patients |
| nurse.anita | Nurse@123 | NURSE (Cardiology) | 18 |
| nurse.ravi | Nurse@123 | NURSE (Neurology) | 16 |
| reception | Reception@123 | RECEPTIONIST | non-VIP only |
| intern | Intern@123 | INTERN | 0 |

## 5. Suggested demo script (for the viva)
1. Sign in as **dr.mehta**, then **nurse.anita**, then **reception**. Same *Patients* page, different rows and columns.
2. As **nurse.anita**, edit a patient and change the ward to *Neurology*. The trigger rejects it (update_check).
3. As **reception**, register a patient and tick *VIP*. The insert check blocks it.
4. In the **SQL console**, run `SELECT * FROM patients`. Access is prohibited. `SELECT * FROM vpd_patients WHERE 1=1 OR 1=1` still returns only your rows.
5. As **admin**, open *VPD policies*, disable the RECEPTIONIST policy, then sign in as reception: 0 rows (deny by default). Re-enable it.
6. As **admin**, open the *Policy simulator* to compare every user at a glance.

## 6. Project structure
```
app.py               Flask routes (login, patients, policies, simulator, console)
database.py          Base schema: roles, users, patients, vpd_policies, column_policies
security/vpd.py      VPD engine: application context, policy predicate, secure view, triggers, authorizer
seed.py              Demo roles, users, policies and 60 patients
templates/           Jinja2 pages
static/              CSS and JS
instance/            Generated at runtime: SQLite DB and secret key
```
