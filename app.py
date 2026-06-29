import os
import secrets
import sqlite3
import uuid
from datetime import date, datetime, timezone, timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, abort, render_template, request, redirect, session, url_for
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from database import create_database

app = Flask(__name__)

app.permanent_session_lifetime = timedelta(minutes=10)

configured_secret_key = os.environ.get("SECRET_KEY")
if os.environ.get("FLASK_ENV") == "production" and not configured_secret_key:
    raise RuntimeError("SECRET_KEY must be configured in production.")

app.config.update(
    SECRET_KEY=configured_secret_key or "development-only-change-me",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
)

LAB_UPLOAD_FOLDER = Path(app.root_path) / "static" / "uploads" / "lab_reports"
ALLOWED_LAB_FILE_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif"}
LAB_UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

PATIENT_ACCESS_TTL_SECONDS = 15 * 60
DOCTOR_ROLES = {"assistenzarzt", "oberarzt", "chefarzt"}
NURSE_ROLES = {"nurse", "nurse_48", "nurse_49"}
CLINICAL_ROLES = DOCTOR_ROLES | NURSE_ROLES | {"lab"}
SHIFT_ROLES = DOCTOR_ROLES | NURSE_ROLES
def get_today_shift():
    if "username" not in session:
        return None

    user_id = get_session_user_id()
    if not user_id:
        return None

    connection = get_db_connection()
    shift = connection.execute("""
        SELECT shift_type FROM duty_shifts
        WHERE user_id = ? AND duty_date = ?
    """, (user_id, date.today().isoformat())).fetchone()

    connection.close()

    return shift["shift_type"] if shift else None

ROLE_ACCESS_REASONS = {
    "assistenzarzt": ("Behandlung", "Notfall", "Übergabe"),
    "oberarzt": ("Behandlung", "Notfall", "Übergabe"),
    "chefarzt": ("Behandlung", "Notfall", "Übergabe"),
    "nurse": ("Pflege", "Notfall", "Übergabe"),
    "nurse_48": ("Pflege", "Notfall", "Übergabe"),
    "nurse_49": ("Pflege", "Notfall", "Übergabe"),
    "lab": ("Laboruntersuchung", "Notfall"),
    "admin": ("Administrative Prüfung",),
}
VALID_ACCESS_REASONS = {
    reason for reasons in ROLE_ACCESS_REASONS.values() for reason in reasons
}


def normalize_access_reason(reason):
    return (reason or "").replace("Ãœ", "Ü")


def is_allowed_lab_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_LAB_FILE_EXTENSIONS
    )


def save_lab_file(file_storage):
    original_filename = secure_filename(file_storage.filename or "")
    if not original_filename or not is_allowed_lab_file(original_filename):
        return None

    LAB_UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
    extension = original_filename.rsplit(".", 1)[1].lower()
    stored_filename = f"{uuid.uuid4().hex}.{extension}"
    file_storage.save(LAB_UPLOAD_FOLDER / stored_filename)
    return stored_filename, original_filename, extension

DOCTOR_PERMISSIONS = {
        "patients.view", "patient.basic", "diagnosis.view", "medication.view",
        "diagnosis.create", "diagnosis.resolve",
        "medication.create", "lab.view", "vitals.view", "nursing_notes.view",
        "orders.view", "orders.create", "notifications.manage",
        "handover.view", "handover.create", "shifts.set",
        "lab_requests.create", "lab_requests.view", "warnings.create",
}

PERMISSIONS = {
    "assistenzarzt": set(DOCTOR_PERMISSIONS),
    "oberarzt": set(DOCTOR_PERMISSIONS),
    "chefarzt": set(DOCTOR_PERMISSIONS),
    "nurse": {
        "patients.view", "patient.basic", "medication.view", "medication.administer",
        "vitals.view", "vitals.create", "nursing_notes.view", "nursing_notes.create",
        "orders.view", "orders.complete", "notifications.create",
        "handover.view", "handover.create", "shifts.set",
    },
    "nurse_48": {
        "patients.view", "patient.basic", "medication.view", "medication.administer",
        "vitals.view", "vitals.create", "nursing_notes.view", "nursing_notes.create",
        "orders.view", "orders.complete", "notifications.create",
        "handover.view", "handover.create", "shifts.set",
    },
    "nurse_49": {
        "patients.view", "patient.basic", "medication.view", "medication.administer",
        "vitals.view", "vitals.create", "nursing_notes.view", "nursing_notes.create",
        "orders.view", "orders.complete", "notifications.create",
        "handover.view", "handover.create", "shifts.set",
    },
    "lab": {
        "patients.view", "patient.basic", "lab.view", "lab.create",
        "lab_requests.view", "lab_requests.manage",
    },
    "admin": {
        "patients.view", "patient.basic", "patients.manage", "users.manage", "logs.view",
    },
}

create_database()
MEDICATION_CATALOG = {
    # Schmerzmittel / Fieber / Entzündung
    "Ibuprofen": {
        "category": "Schmerzmittel / Entzündungshemmer",
        "description": "Wirkt schmerzlindernd, fiebersenkend und entzündungshemmend."
    },
    "Paracetamol": {
        "category": "Schmerzmittel / Fiebersenker",
        "description": "Wirkt schmerzlindernd und fiebersenkend, aber kaum entzündungshemmend."
    },
    "Metamizol": {
        "category": "Starkes Schmerzmittel / Fiebersenker",
        "description": "Wird häufig bei stärkeren Schmerzen oder hohem Fieber eingesetzt."
    },
    "Diclofenac": {
        "category": "Schmerzmittel / Entzündungshemmer",
        "description": "Wirkt schmerzlindernd und entzündungshemmend, z. B. bei Gelenk- oder Muskelschmerzen."
    },
    "Morphin": {
        "category": "Starkes Opioid-Schmerzmittel",
        "description": "Wird bei sehr starken Schmerzen eingesetzt."
    },
    "Oxycodon": {
        "category": "Starkes Opioid-Schmerzmittel",
        "description": "Wird zur Behandlung starker Schmerzen eingesetzt."
    },

    # Blutdruck / Herz-Kreislauf
    "Candesartan": {
        "category": "Blutdruckmedikament / AT1-Blocker",
        "description": "Wird zur Behandlung von Bluthochdruck und Herzinsuffizienz eingesetzt."
    },
    "Ramipril": {
        "category": "Blutdruckmedikament / ACE-Hemmer",
        "description": "Senkt den Blutdruck und entlastet das Herz-Kreislauf-System."
    },
    "Amlodipin": {
        "category": "Blutdruckmedikament / Calciumkanalblocker",
        "description": "Erweitert Blutgefäße und senkt dadurch den Blutdruck."
    },
    "Bisoprolol": {
        "category": "Betablocker",
        "description": "Senkt Herzfrequenz und Blutdruck und entlastet das Herz."
    },
    "Metoprolol": {
        "category": "Betablocker",
        "description": "Wird bei Bluthochdruck, Herzrhythmusstörungen oder Herzinsuffizienz eingesetzt."
    },
    "Furosemid": {
        "category": "Diuretikum / Entwässerungstablette",
        "description": "Fördert die Wasserausscheidung und wird z. B. bei Ödemen oder Herzinsuffizienz eingesetzt."
    },
    "Torasemid": {
        "category": "Diuretikum / Entwässerungstablette",
        "description": "Hilft dem Körper, überschüssige Flüssigkeit auszuscheiden."
    },

    # Diabetes / Insulin
    "Metformin": {
        "category": "Diabetesmedikament",
        "description": "Wird bei Diabetes Typ 2 eingesetzt und hilft, den Blutzucker zu senken."
    },
    "Insulin rapid": {
        "category": "Schnell wirksames Insulin",
        "description": "Senkt den Blutzucker schnell, meist im Zusammenhang mit Mahlzeiten."
    },
    "Insulin basal": {
        "category": "Lang wirksames Insulin",
        "description": "Deckt den Grundbedarf an Insulin über einen längeren Zeitraum ab."
    },
    "Insulin glargin": {
        "category": "Langzeitinsulin",
        "description": "Wird zur längerfristigen Blutzuckerkontrolle eingesetzt."
    },
    "Insulin lispro": {
        "category": "Schnell wirksames Insulin",
        "description": "Wird meist zu den Mahlzeiten gegeben, um Blutzuckerspitzen zu senken."
    },
    "Empagliflozin": {
        "category": "Diabetesmedikament / SGLT2-Hemmer",
        "description": "Hilft, Zucker über den Urin auszuscheiden, und wird bei Diabetes Typ 2 eingesetzt."
    },

    # Magen / Verdauung
    "Pantoprazol": {
        "category": "Magenschutz / Protonenpumpenhemmer",
        "description": "Reduziert die Magensäure und wird z. B. bei Reflux oder als Magenschutz genutzt."
    },
    "Omeprazol": {
        "category": "Magenschutz / Protonenpumpenhemmer",
        "description": "Verringert die Magensäureproduktion."
    },
    "Metoclopramid": {
        "category": "Mittel gegen Übelkeit",
        "description": "Wird bei Übelkeit und Erbrechen eingesetzt."
    },
    "Ondansetron": {
        "category": "Mittel gegen Übelkeit",
        "description": "Wird häufig bei starker Übelkeit, z. B. nach Operationen oder Chemotherapie, eingesetzt."
    },
    "Loperamid": {
        "category": "Mittel gegen Durchfall",
        "description": "Verlangsamt die Darmbewegung und kann Durchfall reduzieren."
    },
    "Macrogol": {
        "category": "Abführmittel",
        "description": "Wird bei Verstopfung eingesetzt und macht den Stuhl weicher."
    },

    # Antibiotika
    "Amoxicillin": {
        "category": "Antibiotikum",
        "description": "Wird gegen bestimmte bakterielle Infektionen eingesetzt."
    },
    "Cefuroxim": {
        "category": "Antibiotikum / Cephalosporin",
        "description": "Wird bei verschiedenen bakteriellen Infektionen eingesetzt."
    },
    "Ceftriaxon": {
        "category": "Antibiotikum / Cephalosporin",
        "description": "Wird häufig bei schwereren bakteriellen Infektionen eingesetzt."
    },
    "Piperacillin/Tazobactam": {
        "category": "Breitbandantibiotikum",
        "description": "Wird bei schweren oder komplizierten bakteriellen Infektionen eingesetzt."
    },
    "Clarithromycin": {
        "category": "Antibiotikum / Makrolid",
        "description": "Wird bei bestimmten Atemwegs- oder anderen bakteriellen Infektionen eingesetzt."
    },
    "Ciprofloxacin": {
        "category": "Antibiotikum / Fluorchinolon",
        "description": "Wird bei bestimmten bakteriellen Infektionen eingesetzt."
    },

    # Blutverdünnung / Thromboseprophylaxe
    "Heparin": {
        "category": "Gerinnungshemmer",
        "description": "Hemmt die Blutgerinnung und wird zur Thromboseprophylaxe eingesetzt."
    },
    "Enoxaparin": {
        "category": "Niedermolekulares Heparin",
        "description": "Wird häufig zur Vorbeugung oder Behandlung von Thrombosen eingesetzt."
    },
    "Apixaban": {
        "category": "Oraler Gerinnungshemmer",
        "description": "Wird zur Vorbeugung von Blutgerinnseln eingesetzt."
    },
    "Rivaroxaban": {
        "category": "Oraler Gerinnungshemmer",
        "description": "Hemmt die Blutgerinnung und senkt das Risiko für Thrombosen oder Embolien."
    },
    "ASS 100": {
        "category": "Thrombozytenaggregationshemmer",
        "description": "Hemmt das Verklumpen von Blutplättchen und wird z. B. zum Gefäßschutz eingesetzt."
    },
    "Clopidogrel": {
        "category": "Thrombozytenaggregationshemmer",
        "description": "Wird eingesetzt, um Blutplättchen an der Gerinnung zu hindern."
    },

    # Atemwege
    "Salbutamol": {
        "category": "Asthma-/Atemwegsmedikament",
        "description": "Erweitert die Bronchien und erleichtert das Atmen bei Atemnot."
    },
    "Ipratropiumbromid": {
        "category": "Bronchienerweiterndes Medikament",
        "description": "Wird bei Atemwegserkrankungen eingesetzt, um die Bronchien zu erweitern."
    },
    "Prednisolon": {
        "category": "Kortison / Entzündungshemmer",
        "description": "Wirkt stark entzündungshemmend und wird bei vielen Entzündungsreaktionen eingesetzt."
    },
    "Budesonid": {
        "category": "Inhalatives Kortison",
        "description": "Wirkt entzündungshemmend in den Atemwegen."
    },

    # Psychiatrie / Neurologie
    "Diazepam": {
        "category": "Beruhigungsmittel / Benzodiazepin",
        "description": "Wirkt beruhigend, angstlösend und muskelentspannend."
    },
    "Lorazepam": {
        "category": "Beruhigungsmittel / Benzodiazepin",
        "description": "Wird bei Angst, Unruhe oder Krampfanfällen eingesetzt."
    },
    "Quetiapin": {
        "category": "Antipsychotikum",
        "description": "Wird bei bestimmten psychischen Erkrankungen oder starker Unruhe eingesetzt."
    },
    "Sertralin": {
        "category": "Antidepressivum / SSRI",
        "description": "Wird bei Depressionen und Angststörungen eingesetzt."
    },
    "Levetiracetam": {
        "category": "Antiepileptikum",
        "description": "Wird zur Behandlung und Vorbeugung epileptischer Anfälle eingesetzt."
    },

    # Schilddrüse / Hormone
    "L-Thyroxin": {
        "category": "Schilddrüsenhormon",
        "description": "Wird bei Schilddrüsenunterfunktion eingesetzt."
    },
    "Hydrocortison": {
        "category": "Kortison / Hormonpräparat",
        "description": "Wird bei bestimmten Hormonmangelzuständen oder Entzündungen eingesetzt."
    },

    # Elektrolyte / Infusionen
    "NaCl 0,9%": {
        "category": "Infusionslösung",
        "description": "Wird zur Flüssigkeitsgabe oder als Trägerlösung verwendet."
    },
    "Ringerlösung": {
        "category": "Infusionslösung",
        "description": "Dient zur Flüssigkeits- und Elektrolytzufuhr."
    },
    "Kaliumchlorid": {
        "category": "Elektrolytersatz",
        "description": "Wird bei Kaliummangel eingesetzt."
    },
    "Magnesium": {
        "category": "Elektrolytersatz",
        "description": "Wird bei Magnesiummangel oder bestimmten Muskel- und Herzproblemen eingesetzt."
    },

    # Sonstiges
    "Atorvastatin": {
        "category": "Cholesterinsenker / Statin",
        "description": "Senkt Blutfette und wird zur Vorbeugung von Herz-Kreislauf-Erkrankungen eingesetzt."
    },
    "Simvastatin": {
        "category": "Cholesterinsenker / Statin",
        "description": "Hilft, erhöhte Cholesterinwerte zu senken."
    },
    "Allopurinol": {
        "category": "Gichtmedikament",
        "description": "Senkt den Harnsäurespiegel und wird bei Gicht eingesetzt."
    },
    "Folsäure": {
        "category": "Vitaminpräparat",
        "description": "Wird bei Folsäuremangel oder erhöhtem Bedarf eingesetzt."
    },
    "Vitamin D": {
        "category": "Vitaminpräparat",
        "description": "Wird bei Vitamin-D-Mangel oder zur Unterstützung des Knochenstoffwechsels eingesetzt."
    }
}

def get_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token

@app.before_request
def check_session_timeout():
    # Diese Endpunkte sollen den Inaktivitäts-Timer nicht verlängern.
    allowed_routes = {"login", "logout", "static", "autosave_draft"}

    if request.endpoint in allowed_routes:
        return

    if "username" not in session:
        return

    last_activity = session.get("last_activity")

    if last_activity:
        last_activity_time = datetime.fromisoformat(last_activity)
        now = datetime.now()

        if now - last_activity_time > timedelta(minutes=10):
            session.clear()
            return redirect(url_for("login"))

    session["last_activity"] = datetime.now().isoformat()


@app.context_processor
def inject_csrf_token():
    return {
        "csrf_token": get_csrf_token,
        "is_doctor_role": is_doctor_role,
        "is_nurse_role": is_nurse_role,
        "role_label": get_role_label,
        "has_permission": has_permission,
    }


@app.before_request
def protect_post_requests():
    if request.method != "POST":
        return None

    expected = session.get("csrf_token", "")
    submitted = request.form.get("csrf_token", "")
    if not expected or not secrets.compare_digest(expected, submitted):
        abort(400, description="Ungültiges oder fehlendes CSRF-Token.")
    return None

@app.before_request
def require_shift_selection():
    if app.config.get("TESTING"):
        return None

    allowed_endpoints = {
        "login",
        "logout",
        "choose_shift",
        "set_shift",
        "autosave_draft",
        "static",
    }

    if request.endpoint in allowed_endpoints:
        return None

    if "username" not in session:
        return None

    if session.get("role") not in SHIFT_ROLES:
        return None

    if not get_today_shift():
        return redirect(url_for("choose_shift"))

    return None

def get_db_connection():
    connection = sqlite3.connect("hospital.db")
    connection.row_factory = sqlite3.Row
    return connection
def get_role_label(role):
    role_labels = {
        "assistenzarzt": "Assistenzarzt / Assistenzärztin",
        "oberarzt": "Oberarzt / Oberärztin",
        "chefarzt": "Chefarzt / Chefärztin",
        "nurse": "Pflegekraft",
        "nurse_48": "Pflegekraft Station 48",
        "nurse_49": "Pflegekraft Station 49",
        "lab": "Laborpersonal",
        "admin": "Administrator"
    }

    return role_labels.get(role, role)


def is_doctor_role(role):
    return role in DOCTOR_ROLES


def is_nurse_role(role):
    return role in NURSE_ROLES


def get_session_user_id():
    user_id = session.get("user_id")
    if user_id:
        return user_id

    connection = get_db_connection()
    user = connection.execute(
        "SELECT id FROM users WHERE username = ?", (session.get("username"),)
    ).fetchone()
    connection.close()
    if user:
        session["user_id"] = user["id"]
        return user["id"]
    return None


def get_accessible_station_ids():
    role = session.get("role")

    connection = get_db_connection()

    if role in {"admin", "chefarzt"}:
        rows = connection.execute("""
            SELECT id FROM stations
            ORDER BY station_number
        """).fetchall()

        connection.close()
        return [row["id"] for row in rows]

    if role in {"nurse_48", "nurse_49"}:
        station_number = "48" if role == "nurse_48" else "49"
        row = connection.execute("""
            SELECT id FROM stations
            WHERE station_number = ?
        """, (station_number,)).fetchone()

        connection.close()
        return [row["id"]] if row else []

    current_shift = get_today_shift()

    if current_shift == "Nachtdienst":
        rows = connection.execute("""
            SELECT id FROM stations
            WHERE station_number IN (?, ?)
            ORDER BY station_number
        """, ("48", "49")).fetchall()

        connection.close()
        return [row["id"] for row in rows]

    rows = connection.execute("""
        SELECT station_id FROM user_stations
        WHERE user_id = ?
        ORDER BY station_id
    """, (get_session_user_id(),)).fetchall()

    connection.close()
    return [row["station_id"] for row in rows]

def can_access_station(station_id):
    return station_id is not None and station_id in get_accessible_station_ids()


def can_access_patient(patient_id):
    connection = get_db_connection()
    if session.get("role") == "admin":
        patient = connection.execute(
            "SELECT id FROM patients WHERE id = ?", (patient_id,)
        ).fetchone()
        connection.close()
        return patient is not None
    patient = connection.execute("""
        SELECT station_id FROM current_patient_locations WHERE patient_id = ?
    """, (patient_id,)).fetchone()
    connection.close()
    return patient is not None and can_access_station(patient["station_id"])


def safe_count(query):
    try:
        connection = get_db_connection()
        result = connection.execute(query).fetchone()[0]
        connection.close()
        return result
    except sqlite3.OperationalError:
        return 0


def has_permission(role, data_type):
    legacy_permissions = {
        "basic": "patient.basic",
        "diagnosis": "diagnosis.view",
        "medication": "medication.view",
        "lab_results": "lab.view",
        "vital_values": "vitals.view",
        "logs": "logs.view",
    }
    permission = legacy_permissions.get(data_type, data_type)
    return permission in PERMISSIONS.get(role, set())


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def permission_required(permission):
    def decorator(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            if "username" not in session:
                return redirect(url_for("login"))
            if not has_permission(session.get("role"), permission):
                abort(403)
            return view(*args, **kwargs)

        return wrapped_view

    return decorator


def log_access(username, role, patient_id, patient_name, accessed_data, access_reason, action="view"):
    connection = get_db_connection()

    connection.execute("""
        INSERT INTO access_logs (
            username, role, patient_id, patient_name, accessed_data, access_reason, action
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (username, role, patient_id, patient_name, accessed_data, access_reason, action))

    connection.commit()
    connection.close()


def unlock_patient_access(patient_id, access_reason):
    session[f"patient_access_{patient_id}"] = {
        "reason": access_reason,
        "granted_at": datetime.now(timezone.utc).timestamp(),
    }


def has_unlocked_patient_access(patient_id):
    grant = session.get(f"patient_access_{patient_id}")
    if not isinstance(grant, dict):
        return False

    granted_at = grant.get("granted_at", 0)
    age = datetime.now(timezone.utc).timestamp() - granted_at
    if age > PATIENT_ACCESS_TTL_SECONDS:
        session.pop(f"patient_access_{patient_id}", None)
        return False
    return normalize_access_reason(grant.get("reason")) in ROLE_ACCESS_REASONS.get(session.get("role"), ())


def get_patient_access_reason(patient_id):
    grant = session.get(f"patient_access_{patient_id}", {})
    return grant.get("reason") if isinstance(grant, dict) else None


def audit_patient_access(patient, accessed_data, action="view"):
    log_access(
        session["username"],
        session["role"],
        patient["id"],
        patient["name"],
        accessed_data,
        get_patient_access_reason(patient["id"]),
        action,
    )

def require_patient_access(patient_id):
    if not can_access_patient(patient_id):
        abort(403)

    if not has_unlocked_patient_access(patient_id):
        next_url = request.full_path if request.query_string else request.path
        return redirect(url_for(
            "patient_detail",
            patient_id=patient_id,
            next=next_url
        ))

    return None

def create_draft_and_letter_tables():
    connection = get_db_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS drafts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            patient_id INTEGER,
            draft_type TEXT NOT NULL,
            content TEXT NOT NULL,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, patient_id, draft_type)
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS doctor_letters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            author_user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


create_draft_and_letter_tables()


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        connection = get_db_connection()

        user = connection.execute("""
            SELECT * FROM users
            WHERE username = ? AND is_active = 1
        """, (username,)).fetchone()

        connection.close()

        if (
            user
            and user["role"] in PERMISSIONS
            and check_password_hash(user["password"], password)
        ):
            session.clear()
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["user_id"] = user["id"]
            session.permanent = True
            session["last_activity"] = datetime.now().isoformat()

            if user["role"] in SHIFT_ROLES:
                return redirect(url_for("choose_shift"))

            return redirect(url_for("dashboard"))

        error = "Falscher Benutzername oder falsches Passwort."

    return render_template("login.html", error=error)

@app.route("/choose_shift", methods=["GET", "POST"])
def choose_shift():
    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in SHIFT_ROLES:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        shift_type = request.form.get("shift_type")

        if shift_type not in ["Tagdienst", "Spätdienst", "Nachtdienst"]:
            return "Ungültiger Dienst.", 400

        connection = get_db_connection()

        connection.execute("""
            INSERT INTO duty_shifts (user_id, duty_date, shift_type)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id, duty_date) DO UPDATE SET
                shift_type = excluded.shift_type,
                updated_at = CURRENT_TIMESTAMP
        """, (get_session_user_id(), date.today().isoformat(), shift_type))

        connection.commit()
        connection.close()

        return redirect(url_for("dashboard"))

    return render_template("choose_shift.html")


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    notifications = []
    role = session["role"]

    connection = get_db_connection()

    # Stationen über Dienst + Benutzerzuweisung holen
    station_ids = get_accessible_station_ids()

    # Patienten zählen
    if station_ids:
        placeholders = ",".join("?" for _ in station_ids)

        patient_count = connection.execute(
            f"""
            SELECT COUNT(*)
            FROM current_patient_locations
            WHERE station_id IN ({placeholders})
            """,
            station_ids
        ).fetchone()[0]
    else:
        patient_count = 0

    user_count = safe_count("SELECT COUNT(*) FROM users")
    access_logs_count = safe_count("SELECT COUNT(*) FROM access_logs")

    open_orders_count = 0
    open_medications_count = 0
    open_notifications_count = 0
    urgent_patients = []
    nurse_order_tasks = []
    nurse_medication_tasks = []
    latest_lab_reports = []
    pending_lab_requests = []
    critical_lab_reports = []
    draft_count = 0

    if station_ids:
        placeholders = ",".join("?" for _ in station_ids)

        open_orders_count = connection.execute(
            f"""
            SELECT COUNT(*)
            FROM doctor_orders
            JOIN current_patient_locations locations
              ON locations.patient_id = doctor_orders.patient_id
            WHERE doctor_orders.status = 'offen'
              AND locations.station_id IN ({placeholders})
            """,
            station_ids
        ).fetchone()[0]

        urgent_patients = connection.execute(
            f"""
            SELECT DISTINCT
                patients.id,
                patients.name,
                locations.station_number,
                locations.room_number,
                locations.bed_label,
                vital_signs.record_date,
                vital_signs.record_time,
                vital_signs.pulse,
                vital_signs.temperature,
                vital_signs.oxygen_saturation
            FROM vital_signs
            JOIN patients ON patients.id = vital_signs.patient_id
            JOIN current_patient_locations locations
              ON locations.patient_id = patients.id
            WHERE locations.station_id IN ({placeholders})
              AND (
                vital_signs.pulse > 100
                OR vital_signs.temperature >= 38.0
                OR vital_signs.oxygen_saturation < 94
              )
            ORDER BY vital_signs.record_date DESC, vital_signs.record_time DESC
            LIMIT 5
            """,
            station_ids
        ).fetchall()

        if is_nurse_role(role):
            nurse_order_tasks = connection.execute(
                f"""
                SELECT doctor_orders.*, patients.name AS patient_name,
                       locations.station_number, locations.room_number, locations.bed_label
                FROM doctor_orders
                JOIN patients ON patients.id = doctor_orders.patient_id
                JOIN current_patient_locations locations
                  ON locations.patient_id = patients.id
                WHERE doctor_orders.status = 'offen'
                  AND locations.station_id IN ({placeholders})
                ORDER BY doctor_orders.created_at DESC
                LIMIT 5
                """,
                station_ids
            ).fetchall()

            nurse_medication_tasks = connection.execute(
                f"""
                SELECT medication_plan.*, patients.name AS patient_name,
                       locations.station_number, locations.room_number, locations.bed_label
                FROM medication_plan
                JOIN patients ON patients.id = medication_plan.patient_id
                JOIN current_patient_locations locations
                  ON locations.patient_id = patients.id
                WHERE medication_plan.status = 'offen'
                  AND locations.station_id IN ({placeholders})
                ORDER BY medication_plan.schedule_time
                LIMIT 5
                """,
                station_ids
            ).fetchall()

        if is_doctor_role(role):
            latest_lab_reports = connection.execute(
                f"""
                SELECT lab_reports.*, patients.name AS patient_name,
                       locations.station_number, locations.room_number, locations.bed_label
                FROM lab_reports
                JOIN patients ON patients.id = lab_reports.patient_id
                JOIN current_patient_locations locations
                  ON locations.patient_id = patients.id
                WHERE locations.station_id IN ({placeholders})
                ORDER BY lab_reports.created_at DESC
                LIMIT 5
                """,
                station_ids
            ).fetchall()

            critical_lab_reports = connection.execute(
                f"""
                SELECT lab_reports.*, patients.name AS patient_name,
                       locations.station_number, locations.room_number, locations.bed_label
                FROM lab_reports
                JOIN patients ON patients.id = lab_reports.patient_id
                JOIN current_patient_locations locations
                  ON locations.patient_id = patients.id
                WHERE locations.station_id IN ({placeholders})
                  AND lab_reports.status = 'kritisch'
                ORDER BY lab_reports.created_at DESC
                LIMIT 5
                """,
                station_ids
            ).fetchall()

            draft_count = connection.execute(
                """
                SELECT COUNT(*) FROM drafts
                WHERE user_id = ? AND draft_type = 'arztbrief'
                """,
                (get_session_user_id(),)
            ).fetchone()[0]

        if has_permission(role, "lab_requests.view"):
            pending_lab_requests = connection.execute(
                f"""
                SELECT lab_requests.*, patients.name AS patient_name,
                       users.username AS requested_by,
                       locations.station_number, locations.room_number, locations.bed_label
                FROM lab_requests
                JOIN patients ON patients.id = lab_requests.patient_id
                JOIN users ON users.id = lab_requests.requested_by_user_id
                JOIN current_patient_locations locations
                  ON locations.patient_id = patients.id
                WHERE lab_requests.status IN ('offen', 'in Arbeit')
                  AND locations.station_id IN ({placeholders})
                ORDER BY
                  CASE lab_requests.priority
                    WHEN 'kritisch' THEN 1
                    WHEN 'dringend' THEN 2
                    ELSE 3
                  END,
                  lab_requests.created_at DESC
                LIMIT 6
                """,
                station_ids
            ).fetchall()

        open_medications_count = connection.execute(
            f"""
            SELECT COUNT(*)
            FROM medication_plan
            JOIN current_patient_locations locations
              ON locations.patient_id = medication_plan.patient_id
            WHERE medication_plan.status = 'offen'
              AND locations.station_id IN ({placeholders})
            """,
            station_ids
        ).fetchone()[0]

        open_notifications_count = connection.execute(
            f"""
            SELECT COUNT(*)
            FROM doctor_notifications
            JOIN current_patient_locations locations
              ON locations.patient_id = doctor_notifications.patient_id
            WHERE doctor_notifications.status = 'offen'
              AND locations.station_id IN ({placeholders})
            """,
            station_ids
        ).fetchone()[0]

    # Arzt-Benachrichtigungen
    if is_doctor_role(role) and station_ids:
        try:
            placeholders = ",".join("?" for _ in station_ids)

            notifications = connection.execute(
                f"""
                SELECT doctor_notifications.*, patients.name AS patient_name
                FROM doctor_notifications
                JOIN patients ON doctor_notifications.patient_id = patients.id
                JOIN current_patient_locations locations
                  ON locations.patient_id = patients.id
                WHERE doctor_notifications.status = 'offen'
                  AND locations.station_id IN ({placeholders})
                ORDER BY doctor_notifications.created_at DESC
                """,
                station_ids
            ).fetchall()

        except sqlite3.OperationalError:
            notifications = []

    # Aktueller Dienst aus duty_shifts holen
    current_shift = None

    if role in SHIFT_ROLES:
        shift_row = connection.execute(
            """
            SELECT shift_type
            FROM duty_shifts
            WHERE user_id = ? AND duty_date = ?
            """,
            (get_session_user_id(), date.today().isoformat())
        ).fetchone()

        if shift_row:
            current_shift = shift_row["shift_type"]

    # Sichtbare Stationen fürs Dashboard anzeigen
    if station_ids:
        placeholders = ",".join("?" for _ in station_ids)

        stations = connection.execute(
            f"""
            SELECT id, station_number, name
            FROM stations
            WHERE id IN ({placeholders})
            ORDER BY station_number
            """,
            station_ids
        ).fetchall()
    else:
        stations = []

    connection.close()

    return render_template(
        "dashboard.html",
        username=session["username"],
        role=role,
        role_label=get_role_label(role),
        notifications=notifications,
        patient_count=patient_count,
        user_count=user_count,
        open_orders_count=open_orders_count,
        open_medications_count=open_medications_count,
        open_notifications_count=open_notifications_count,
        access_logs_count=access_logs_count,
        current_shift=current_shift,
        stations=stations,
        is_doctor=is_doctor_role(role),
        urgent_patients=urgent_patients,
        nurse_order_tasks=nurse_order_tasks,
        nurse_medication_tasks=nurse_medication_tasks,
        latest_lab_reports=latest_lab_reports,
        critical_lab_reports=critical_lab_reports,
        pending_lab_requests=pending_lab_requests,
        draft_count=draft_count,
    )

@app.route("/patients")
def patients():
    if "username" not in session:
        return redirect(url_for("login"))

    if not has_permission(session["role"], "patients.view"):
        abort(403)

    search_query = request.args.get("search", "")

    connection = get_db_connection()

    station_ids = get_accessible_station_ids()

    # Admin sieht alle Patienten
    if session["role"] == "admin":
        query = """
            SELECT patients.*, locations.station_number, locations.room_number,
                   locations.bed_label, locations.admission_id,
                   (
                     SELECT COUNT(*)
                     FROM vital_signs
                     WHERE vital_signs.patient_id = patients.id
                       AND (
                         vital_signs.pulse > 100
                         OR vital_signs.temperature >= 38.0
                         OR vital_signs.oxygen_saturation < 94
                       )
                   ) AS abnormal_vitals_count
            FROM patients
            LEFT JOIN current_patient_locations locations
              ON locations.patient_id = patients.id
            WHERE 1 = 1
        """
        parameters = []

        if search_query:
            query += " AND patients.name LIKE ?"
            parameters.append(f"%{search_query}%")

        query += " ORDER BY locations.station_number, locations.room_number, patients.name"

        patient_list = connection.execute(query, parameters).fetchall()

    # Nicht-Admin ohne Stationszuweisung sieht einfach keine Patienten,
    # wird aber NICHT zum Login geschickt
    elif not station_ids:
        patient_list = []

    else:
        placeholders = ",".join("?" for _ in station_ids)

        query = f"""
            SELECT patients.*, locations.station_number, locations.room_number,
                   locations.bed_label, locations.admission_id,
                   (
                     SELECT COUNT(*)
                     FROM vital_signs
                     WHERE vital_signs.patient_id = patients.id
                       AND (
                         vital_signs.pulse > 100
                         OR vital_signs.temperature >= 38.0
                         OR vital_signs.oxygen_saturation < 94
                       )
                   ) AS abnormal_vitals_count
            FROM patients
            JOIN current_patient_locations locations
              ON locations.patient_id = patients.id
            WHERE locations.station_id IN ({placeholders})
        """

        parameters = list(station_ids)

        if search_query:
            query += " AND patients.name LIKE ?"
            parameters.append(f"%{search_query}%")

        query += " ORDER BY locations.station_number, locations.room_number, patients.name"

        patient_list = connection.execute(query, parameters).fetchall()

    connection.close()

    return render_template(
        "patients.html",
        patients=patient_list,
        search_query=search_query
    )

@app.route("/patient/<int:patient_id>", methods=["GET", "POST"])
def patient_detail(patient_id):
    if "username" not in session:
        return redirect(url_for("login"))

    if not has_permission(session["role"], "patient.basic"):
        abort(403)

    if not can_access_patient(patient_id):
        abort(403)

    connection = get_db_connection()

    patient = connection.execute("""
        SELECT
            patients.*,
            locations.station_number AS station,
            locations.station_number,
            locations.room_number,
            locations.bed_label,
            locations.admission_id,
            (
                SELECT diagnosis_text
                FROM patient_diagnoses
                WHERE patient_diagnoses.patient_id = patients.id
                  AND patient_diagnoses.status = 'active'
                ORDER BY diagnosed_at DESC
                LIMIT 1
            ) AS diagnosis
        FROM patients
        LEFT JOIN current_patient_locations locations
          ON locations.patient_id = patients.id
        WHERE patients.id = ?
    """, (patient_id,)).fetchone()

    if patient is None:
        connection.close()
        return "Patient wurde nicht gefunden."

    visible_data = None
    access_reason = None

    if request.method == "POST":
        access_reason = normalize_access_reason(request.form.get("access_reason", ""))

        if access_reason not in ROLE_ACCESS_REASONS.get(session["role"], ()):
            connection.close()
            return "Ungültiger Zugriffsgrund.", 400

        unlock_patient_access(patient_id, access_reason)

        next_url = request.form.get("next") or request.args.get("next")

        if next_url and next_url.startswith("/") and not next_url.startswith("//"):
            connection.close()
            return redirect(next_url)

        role = session["role"]
        username = session["username"]

        visible_data = {}

        if has_permission(role, "basic"):
            visible_data["Name"] = patient["name"]
            visible_data["Geburtsdatum"] = patient["birthdate"]
            log_access(username, role, patient_id, patient["name"], "Stammdaten", access_reason)

        if has_permission(role, "diagnosis"):
            log_access(username, role, patient_id, patient["name"], "Diagnose", access_reason)

    medications = connection.execute("""
        SELECT
            medication_plan.*,
            medication_name AS name
        FROM medication_plan
        WHERE patient_id = ?
        ORDER BY schedule_time
    """, (patient_id,)).fetchall()

    nursing_notes = connection.execute("""
        SELECT
            nursing_notes.*,
            nurse_username AS created_by,
            note_text AS note
        FROM nursing_notes
        WHERE patient_id = ?
        ORDER BY created_at DESC
    """, (patient_id,)).fetchall()

    doctor_orders = connection.execute("""
        SELECT
            doctor_orders.*,
            'Ärztliche Anordnung' AS title,
            order_text AS description
        FROM doctor_orders
        WHERE patient_id = ?
        ORDER BY created_at DESC
    """, (patient_id,)).fetchall()

    lab_reports = connection.execute("""
        SELECT
            lab_reports.*,
            test_name AS parameter,
            result_value AS value
        FROM lab_reports
        WHERE patient_id = ?
        ORDER BY created_at DESC
    """, (patient_id,)).fetchall()

    diagnoses = connection.execute("""
        SELECT patient_diagnoses.*,
               diagnosed_by.username AS diagnosed_by,
               resolved_by.username AS resolved_by
        FROM patient_diagnoses
        LEFT JOIN users diagnosed_by
          ON diagnosed_by.id = patient_diagnoses.diagnosed_by_user_id
        LEFT JOIN users resolved_by
          ON resolved_by.id = patient_diagnoses.resolved_by_user_id
        WHERE patient_diagnoses.patient_id = ?
        ORDER BY patient_diagnoses.status, patient_diagnoses.diagnosed_at DESC
    """, (patient_id,)).fetchall()

    patient_warnings = connection.execute("""
        SELECT * FROM patient_warnings
        WHERE patient_id = ? AND is_active = 1
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'warning' THEN 2
                ELSE 3
            END,
            created_at DESC
    """, (patient_id,)).fetchall()

    access_logs = []
    try:
        table_info = connection.execute("PRAGMA table_info(access_logs)").fetchall()
        columns = [row["name"] for row in table_info]

        if "patient_id" in columns:
            reason_col = None
            for col in ["reason", "access_reason", "begruendung"]:
                if col in columns:
                    reason_col = col
                    break

            time_col = None
            for col in ["timestamp", "created_at", "accessed_at", "created_on", "time"]:
                if col in columns:
                    time_col = col
                    break

            reason_expr = f"access_logs.{reason_col}" if reason_col else "''"
            time_expr = f"access_logs.{time_col}" if time_col else "''"
            order_expr = f"access_logs.{time_col} DESC" if time_col else (
                "access_logs.id DESC" if "id" in columns else "access_logs.rowid DESC"
            )

            access_logs = connection.execute(f"""
                SELECT
                    username,
                    role,
                    {reason_expr} AS reason,
                    {time_expr} AS timestamp
                FROM access_logs
                WHERE patient_id = ?
                ORDER BY {order_expr}
            """, (patient_id,)).fetchall()
    except sqlite3.OperationalError:
        access_logs = []

    access_unlocked = has_unlocked_patient_access(patient_id)
    handover_notes = []
    lab_files_by_report = {}
    if not access_unlocked:
        medications = []
        nursing_notes = []
        doctor_orders = []
        lab_reports = []
        diagnoses = []
        access_logs = []
        patient_warnings = []
    else:
        if session["role"] != "admin":
            access_logs = []

        if has_permission(session["role"], "handover.view"):
            handover_notes = connection.execute("""
                SELECT handover_notes.*, users.username
                FROM handover_notes
                JOIN users ON users.id = handover_notes.author_user_id
                WHERE handover_notes.patient_id = ?
                ORDER BY handover_notes.created_at DESC
                LIMIT 8
            """, (patient_id,)).fetchall()

        if lab_reports:
            lab_report_ids = [lab["id"] for lab in lab_reports]
            placeholders = ",".join("?" for _ in lab_report_ids)
            lab_files = connection.execute(f"""
                SELECT * FROM lab_report_files
                WHERE lab_report_id IN ({placeholders})
                ORDER BY uploaded_at DESC
            """, lab_report_ids).fetchall()
            for file in lab_files:
                lab_files_by_report.setdefault(file["lab_report_id"], []).append(file)

    connection.close()

    return render_template(
        "patient_detail.html",
        patient=patient,
        visible_data=visible_data,
        access_reason=access_reason,
        medications=medications,
        nursing_notes=nursing_notes,
        doctor_orders=doctor_orders,
        lab_reports=lab_reports,
        lab_files_by_report=lab_files_by_report,
        diagnoses=diagnoses,
        patient_warnings=patient_warnings,
        access_logs=access_logs,
        handover_notes=handover_notes,
        role=session["role"],
        access_unlocked=access_unlocked,
        show_access_logs=session["role"] == "admin",
        allowed_access_reasons=ROLE_ACCESS_REASONS.get(session["role"], ()),
    )
@app.route("/patient/<int:patient_id>/arztbrief", methods=["GET", "POST"])
def arztbrief(patient_id):
    if "username" not in session:
        return redirect(url_for("login"))

    if not is_doctor_role(session.get("role")):
        abort(403)

    access_check = require_patient_access(patient_id)
    if access_check:
        return access_check

    connection = get_db_connection()

    patient = connection.execute("""
        SELECT * FROM patients
        WHERE id = ?
    """, (patient_id,)).fetchone()

    if not patient:
        connection.close()
        abort(404)

    if request.method == "POST":
        title = request.form.get("title", "Arztbrief").strip()
        content = request.form.get("arztbrief_content", "").strip()

        if not content:
            connection.close()
            return "Der Arztbrief darf nicht leer sein.", 400

        connection.execute("""
            INSERT INTO doctor_letters (
                patient_id, author_user_id, title, content
            )
            VALUES (?, ?, ?, ?)
        """, (patient_id, get_session_user_id(), title, content))

        connection.execute("""
            DELETE FROM drafts
            WHERE user_id = ? AND patient_id = ? AND draft_type = ?
        """, (get_session_user_id(), patient_id, "arztbrief"))

        connection.commit()
        connection.close()

        audit_patient_access(patient, "Arztbrief", "create")

        return redirect(url_for("patient_detail", patient_id=patient_id))

    draft = connection.execute("""
        SELECT content FROM drafts
        WHERE user_id = ? AND patient_id = ? AND draft_type = ?
    """, (get_session_user_id(), patient_id, "arztbrief")).fetchone()

    draft_content = draft["content"] if draft else ""

    connection.close()

    return render_template(
        "arztbrief.html",
        patient=patient,
        draft_content=draft_content
    )


@app.route("/autosave_draft", methods=["POST"])
def autosave_draft():
    if "username" not in session:
        return {"success": False, "message": "Nicht eingeloggt"}, 401

    user_id = session.get("user_id")
    patient_id = request.form.get("patient_id")
    draft_type = request.form.get("draft_type")
    content = request.form.get("content", "")

    if not draft_type:
        return {"success": False, "message": "Draft-Typ fehlt"}, 400

    connection = get_db_connection()

    connection.execute("""
        INSERT INTO drafts (user_id, patient_id, draft_type, content, updated_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id, patient_id, draft_type) DO UPDATE SET
            content = excluded.content,
            updated_at = CURRENT_TIMESTAMP
    """, (user_id, patient_id, draft_type, content))

    connection.commit()
    connection.close()

    return {"success": True}


@app.route("/doctor_drafts")
def doctor_drafts():
    if "username" not in session:
        return redirect(url_for("login"))

    if not is_doctor_role(session.get("role")):
        abort(403)

    connection = get_db_connection()
    station_ids = get_accessible_station_ids()
    drafts = []

    if station_ids:
        placeholders = ",".join("?" for _ in station_ids)
        drafts = connection.execute(f"""
            SELECT
                drafts.*,
                patients.name AS patient_name,
                patients.birthdate,
                locations.station_number,
                locations.room_number,
                locations.bed_label
            FROM drafts
            JOIN patients ON patients.id = drafts.patient_id
            JOIN current_patient_locations locations
              ON locations.patient_id = patients.id
            WHERE drafts.user_id = ?
              AND drafts.draft_type = 'arztbrief'
              AND locations.station_id IN ({placeholders})
            ORDER BY drafts.updated_at DESC
        """, [get_session_user_id(), *station_ids]).fetchall()

    connection.close()

    return render_template("doctor_drafts.html", drafts=drafts)


@app.route("/add_diagnosis/<int:patient_id>", methods=["POST"])
def add_diagnosis(patient_id):
    if "username" not in session:
        return redirect(url_for("login"))
    if not has_permission(session["role"], "diagnosis.create"):
        abort(403)
    access_check = require_patient_access(patient_id)
    if access_check:
        return access_check

    diagnosis_text = request.form.get("diagnosis_text", "").strip()
    if not diagnosis_text or len(diagnosis_text) > 500:
        return "Die Diagnose muss 1 bis 500 Zeichen enthalten.", 400

    connection = get_db_connection()
    patient = connection.execute(
        "SELECT * FROM patients WHERE id = ?", (patient_id,)
    ).fetchone()
    if not patient:
        connection.close()
        abort(404)
    connection.execute("""
        INSERT INTO patient_diagnoses (
            patient_id, diagnosis_text, diagnosed_by_user_id
        ) VALUES (?, ?, ?)
    """, (patient_id, diagnosis_text, get_session_user_id()))
    connection.commit()
    connection.close()
    audit_patient_access(patient, "Diagnosen", "create")
    return redirect(url_for("patient_detail", patient_id=patient_id))


@app.route("/resolve_diagnosis/<int:diagnosis_id>", methods=["POST"])
def resolve_diagnosis(diagnosis_id):
    if "username" not in session:
        return redirect(url_for("login"))
    if not has_permission(session["role"], "diagnosis.resolve"):
        abort(403)

    connection = get_db_connection()
    diagnosis = connection.execute("""
        SELECT patient_diagnoses.*, patients.name
        FROM patient_diagnoses
        JOIN patients ON patients.id = patient_diagnoses.patient_id
        WHERE patient_diagnoses.id = ?
    """, (diagnosis_id,)).fetchone()
    if not diagnosis:
        connection.close()
        abort(404)
    if diagnosis["status"] != "active":
        connection.close()
        return "Diese Diagnose ist bereits abgeschlossen.", 409
    access_check = require_patient_access(diagnosis["patient_id"])
    if access_check:
        connection.close()
        return access_check

    resolution_note = request.form.get("resolution_note", "").strip()
    if not resolution_note or len(resolution_note) > 500:
        connection.close()
        return "Der Abschlussvermerk muss 1 bis 500 Zeichen enthalten.", 400
    connection.execute("""
        UPDATE patient_diagnoses
        SET status = 'resolved', resolved_by_user_id = ?,
            resolved_at = CURRENT_TIMESTAMP, resolution_note = ?
        WHERE id = ? AND status = 'active'
    """, (get_session_user_id(), resolution_note, diagnosis_id))
    connection.commit()
    connection.close()
    audit_patient_access(
        {"id": diagnosis["patient_id"], "name": diagnosis["name"]},
        "Diagnosen",
        "resolve",
    )
    return redirect(url_for("patient_detail", patient_id=diagnosis["patient_id"]))


@app.route("/logs")
def logs():
    if "username" not in session:
        return redirect(url_for("login"))

    if not has_permission(session["role"], "logs.view"):
        abort(403)

    username_filter = request.args.get("username", "").strip()
    role_filter = request.args.get("role", "").strip()
    patient_filter = request.args.get("patient", "").strip()
    reason_filter = request.args.get("reason", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    connection = get_db_connection()

    # Echte Spalten der Tabelle access_logs auslesen
    table_info = connection.execute("PRAGMA table_info(access_logs)").fetchall()
    columns = [row["name"] for row in table_info]

    # Mögliche Spalten automatisch erkennen
    id_expr = "access_logs.id" if "id" in columns else "access_logs.rowid"

    username_col = None
    for col in ["username", "user_name", "user"]:
        if col in columns:
            username_col = col
            break

    role_col = None
    for col in ["role", "user_role"]:
        if col in columns:
            role_col = col
            break

    reason_col = None
    for col in ["reason", "access_reason", "begruendung"]:
        if col in columns:
            reason_col = col
            break

    time_col = None
    for col in ["timestamp", "created_at", "accessed_at", "created_on", "time"]:
        if col in columns:
            time_col = col
            break

    username_expr = f"access_logs.{username_col}" if username_col else "''"
    role_expr = f"access_logs.{role_col}" if role_col else "''"
    reason_expr = f"access_logs.{reason_col}" if reason_col else "''"
    time_expr = f"access_logs.{time_col}" if time_col else "''"

    # Patient entweder über patient_id joinen oder direkt patient_name nutzen
    patient_join = ""
    patient_expr = "''"

    if "patient_id" in columns:
        patient_join = "LEFT JOIN patients ON access_logs.patient_id = patients.id"
        patient_expr = "patients.name"
    elif "patient_name" in columns:
        patient_expr = "access_logs.patient_name"

    query = f"""
        SELECT
            {id_expr} AS id,
            {username_expr} AS username,
            {role_expr} AS role,
            {patient_expr} AS patient_name,
            {reason_expr} AS reason,
            {time_expr} AS timestamp
        FROM access_logs
        {patient_join}
        WHERE 1 = 1
    """

    parameters = []

    if username_filter and username_col:
        query += f" AND access_logs.{username_col} LIKE ?"
        parameters.append(f"%{username_filter}%")

    if role_filter and role_col:
        query += f" AND access_logs.{role_col} = ?"
        parameters.append(role_filter)

    if patient_filter:
        if "patient_id" in columns:
            query += " AND patients.name LIKE ?"
            parameters.append(f"%{patient_filter}%")
        elif "patient_name" in columns:
            query += " AND access_logs.patient_name LIKE ?"
            parameters.append(f"%{patient_filter}%")

    if reason_filter and reason_col:
        query += f" AND access_logs.{reason_col} LIKE ?"
        parameters.append(f"%{reason_filter}%")

    if date_from and time_col:
        query += f" AND DATE(access_logs.{time_col}) >= ?"
        parameters.append(date_from)

    if date_to and time_col:
        query += f" AND DATE(access_logs.{time_col}) <= ?"
        parameters.append(date_to)

    if time_col:
        query += f" ORDER BY access_logs.{time_col} DESC"
    else:
        query += " ORDER BY id DESC"

    logs_list = connection.execute(query, parameters).fetchall()
    connection.close()

    return render_template(
        "logs.html",
        logs=logs_list,
        username_filter=username_filter,
        role_filter=role_filter,
        patient_filter=patient_filter,
        reason_filter=reason_filter,
        date_from=date_from,
        date_to=date_to
    )


@app.route("/add_user", methods=["GET", "POST"])
def add_user():
    if "username" not in session:
        return redirect(url_for("login"))

    if not has_permission(session["role"], "users.manage"):
        abort(403)

    message = None

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form["role"]

        if role not in PERMISSIONS:
            return "Ungültige Rolle.", 400

        connection = get_db_connection()

        try:
            connection.execute("""
                INSERT INTO users (username, password, role)
                VALUES (?, ?, ?)
            """, (username, generate_password_hash(password), role))

            connection.commit()
            message = "Benutzer wurde erfolgreich angelegt."

        except sqlite3.IntegrityError:
            message = "Dieser Benutzername existiert bereits."

        connection.close()

    return render_template("add_user.html", message=message)




@app.route("/users")
def users():
    if "username" not in session:
        return redirect(url_for("login"))

    if not has_permission(session["role"], "users.manage"):
        abort(403)

    connection = get_db_connection()

    user_list = connection.execute("""
        SELECT id, username, role, is_active FROM users
        ORDER BY id
    """).fetchall()

    stations = connection.execute(
        "SELECT * FROM stations ORDER BY station_number"
    ).fetchall()
    assignment_rows = connection.execute(
        "SELECT user_id, station_id FROM user_stations"
    ).fetchall()
    station_assignments = {}
    for row in assignment_rows:
        station_assignments.setdefault(row["user_id"], set()).add(row["station_id"])

    connection.close()

    return render_template(
        "users.html",
        users=user_list,
        stations=stations,
        station_assignments=station_assignments,
    )


@app.route("/set_shift", methods=["POST"])
def set_shift():
    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in SHIFT_ROLES:
        abort(403)

    shift_type = request.form.get("shift_type", "")

    if shift_type not in {"Tagdienst", "Spätdienst", "Nachtdienst"}:
        return "Ungültige Dienstzeit.", 400

    connection = get_db_connection()
    connection.execute("""
        INSERT INTO duty_shifts (user_id, duty_date, shift_type)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id, duty_date) DO UPDATE SET
            shift_type = excluded.shift_type,
            updated_at = CURRENT_TIMESTAMP
    """, (get_session_user_id(), date.today().isoformat(), shift_type))
    connection.commit()
    connection.close()

    return redirect(url_for("dashboard"))

@app.route("/handover")
def handover():
    if "username" not in session:
        return redirect(url_for("login"))
    if not has_permission(session["role"], "handover.view"):
        abort(403)

    station_ids = get_accessible_station_ids()
    connection = get_db_connection()
    stations = connection.execute(
        "SELECT * FROM stations WHERE id IN ({}) ORDER BY station_number".format(
            ",".join("?" for _ in station_ids)
        ),
        station_ids,
    ).fetchall() if station_ids else []

    selected_station_id = request.args.get("station_id", type=int)
    if selected_station_id is None and stations:
        selected_station_id = stations[0]["id"]
    if selected_station_id not in station_ids:
        connection.close()
        if selected_station_id is not None:
            abort(403)
        return render_template(
            "handover.html", stations=[], patients=[], selected_station_id=None,
            unlocked=False, current_shift=None,
            handover_summary={"patient_count": 0, "alert_count": 0, "note_count": 0},
            notes_by_patient={},
            alerts_by_patient={},
        )

    grant = session.get(f"handover_access_{selected_station_id}", {})
    unlocked = (
        isinstance(grant, dict)
        and normalize_access_reason(grant.get("reason")) == "Übergabe"
        and datetime.now(timezone.utc).timestamp() - grant.get("granted_at", 0)
        <= PATIENT_ACCESS_TTL_SECONDS
    )

    patients = []
    notes_by_patient = {}
    alerts_by_patient = {}
    handover_summary = {
        "patient_count": 0,
        "alert_count": 0,
        "note_count": 0,
    }
    if unlocked:
        patients = connection.execute("""
            SELECT patients.*, locations.room_number, locations.station_number,
                   locations.bed_label
            FROM patients
            JOIN current_patient_locations locations ON locations.patient_id = patients.id
            WHERE locations.station_id = ?
            ORDER BY locations.room_number, locations.bed_label, patients.name
        """, (selected_station_id,)).fetchall()

        patient_ids = [patient["id"] for patient in patients]
        if patient_ids:
            placeholders = ",".join("?" for _ in patient_ids)
            note_rows = connection.execute(f"""
                SELECT handover_notes.*, users.username
                FROM handover_notes
                JOIN users ON users.id = handover_notes.author_user_id
                WHERE patient_id IN ({placeholders})
                ORDER BY created_at DESC
            """, patient_ids).fetchall()
            for note in note_rows:
                notes_by_patient.setdefault(note["patient_id"], []).append(note)

            alert_rows = connection.execute(f"""
                SELECT vital_signs.*
                FROM vital_signs
                JOIN (
                    SELECT patient_id, MAX(record_date) AS latest_date
                    FROM vital_signs
                    WHERE patient_id IN ({placeholders})
                    GROUP BY patient_id
                ) latest
                  ON latest.patient_id = vital_signs.patient_id
                 AND latest.latest_date = vital_signs.record_date
                WHERE vital_signs.pulse > 100
                   OR vital_signs.temperature >= 38.0
                   OR vital_signs.oxygen_saturation < 94
                ORDER BY vital_signs.record_date DESC, vital_signs.record_time DESC
            """, patient_ids).fetchall()
            for alert in alert_rows:
                alerts_by_patient.setdefault(alert["patient_id"], []).append(alert)

        patients = sorted(
            patients,
            key=lambda patient: (
                0 if alerts_by_patient.get(patient["id"]) else 1,
                patient["room_number"] or "",
                patient["bed_label"] or "",
                patient["name"],
            )
        )
        handover_summary = {
            "patient_count": len(patients),
            "alert_count": sum(1 for patient in patients if alerts_by_patient.get(patient["id"])),
            "note_count": sum(len(notes_by_patient.get(patient["id"], [])) for patient in patients),
        }

    current_shift_row = connection.execute("""
        SELECT shift_type FROM duty_shifts
        WHERE user_id = ? AND duty_date = ?
    """, (get_session_user_id(), date.today().isoformat())).fetchone()
    connection.close()

    return render_template(
        "handover.html",
        stations=stations,
        patients=patients,
        selected_station_id=selected_station_id,
        unlocked=unlocked,
        current_shift=current_shift_row["shift_type"] if current_shift_row else None,
        notes_by_patient=notes_by_patient,
        alerts_by_patient=alerts_by_patient,
        handover_summary=handover_summary,
    )


@app.route("/handover/unlock", methods=["POST"])
def unlock_handover():
    if "username" not in session:
        return redirect(url_for("login"))
    if not has_permission(session["role"], "handover.view"):
        abort(403)

    station_id = request.form.get("station_id", type=int)
    if station_id not in get_accessible_station_ids():
        abort(403)

    reason = normalize_access_reason(request.form.get("access_reason", ""))
    if reason != "Übergabe" or reason not in ROLE_ACCESS_REASONS.get(session["role"], ()):
        return "Ungültiger Zugriffsgrund.", 400

    granted_at = datetime.now(timezone.utc).timestamp()
    session[f"handover_access_{station_id}"] = {
        "reason": reason,
        "granted_at": granted_at,
    }

    connection = get_db_connection()
    patients = connection.execute(
        """
        SELECT patients.* FROM patients
        JOIN current_patient_locations locations ON locations.patient_id = patients.id
        WHERE locations.station_id = ?
        """, (station_id,)
    ).fetchall()
    connection.close()
    for patient in patients:
        unlock_patient_access(patient["id"], reason)
        audit_patient_access(patient, "Übergabe")

    return redirect(url_for("handover", station_id=station_id))


@app.route("/handover_note/<int:patient_id>", methods=["POST"])
def add_handover_note(patient_id):
    if "username" not in session:
        return redirect(url_for("login"))
    if not has_permission(session["role"], "handover.create"):
        abort(403)

    access_check = require_patient_access(patient_id)
    if access_check:
        return access_check

    note_text = request.form.get("note_text", "").strip()
    if not note_text or len(note_text) > 2000:
        return "Die Übergabeinformation muss 1 bis 2000 Zeichen enthalten.", 400

    connection = get_db_connection()
    shift = connection.execute("""
        SELECT shift_type FROM duty_shifts
        WHERE user_id = ? AND duty_date = ?
    """, (get_session_user_id(), date.today().isoformat())).fetchone()
    if not shift:
        connection.close()
        return "Bitte zuerst den heutigen Dienst eintragen.", 400

    patient = connection.execute("""
        SELECT patients.*, locations.station_id
        FROM patients
        JOIN current_patient_locations locations ON locations.patient_id = patients.id
        WHERE patients.id = ?
    """, (patient_id,)).fetchone()
    if not patient:
        connection.close()
        abort(404)

    connection.execute("""
        INSERT INTO handover_notes (
            patient_id, author_user_id, shift_type, note_text
        ) VALUES (?, ?, ?, ?)
    """, (patient_id, get_session_user_id(), shift["shift_type"], note_text))
    connection.commit()
    station_id = patient["station_id"]
    connection.close()
    audit_patient_access(patient, "Übergabe", "create")
    return redirect(url_for("handover", station_id=station_id))


@app.route("/assign_user_stations/<int:user_id>", methods=["POST"])
def assign_user_stations(user_id):
    if "username" not in session:
        return redirect(url_for("login"))
    if not has_permission(session["role"], "users.manage"):
        abort(403)

    requested_ids = {
        int(value) for value in request.form.getlist("station_ids") if value.isdigit()
    }
    connection = get_db_connection()
    user = connection.execute(
        "SELECT role FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if not user:
        connection.close()
        abort(404)

    valid_ids = {
        row[0] for row in connection.execute("SELECT id FROM stations").fetchall()
    }
    if not requested_ids.issubset(valid_ids):
        connection.close()
        return "Ungültige Stationszuweisung.", 400

    connection.execute("DELETE FROM user_stations WHERE user_id = ?", (user_id,))
    connection.executemany(
        "INSERT INTO user_stations (user_id, station_id) VALUES (?, ?)",
        [(user_id, station_id) for station_id in sorted(requested_ids)],
    )
    connection.commit()
    connection.close()
    return redirect(url_for("users"))


@app.route("/change_role/<int:user_id>", methods=["POST"])
def change_role(user_id):
    if "username" not in session:
        return redirect(url_for("login"))

    if not has_permission(session["role"], "users.manage"):
        abort(403)

    new_role = request.form["role"]

    if new_role not in PERMISSIONS:
        return "Ungültige Rolle.", 400

    connection = get_db_connection()

    connection.execute("""
        UPDATE users
        SET role = ?
        WHERE id = ?
    """, (new_role, user_id))

    connection.commit()
    connection.close()

    return redirect(url_for("users"))


@app.route("/toggle_user/<int:user_id>", methods=["POST"])
def toggle_user(user_id):
    if "username" not in session:
        return redirect(url_for("login"))

    if not has_permission(session["role"], "users.manage"):
        abort(403)

    connection = get_db_connection()

    user = connection.execute("""
        SELECT * FROM users WHERE id = ?
    """, (user_id,)).fetchone()

    if user is None:
        connection.close()
        return "Benutzer wurde nicht gefunden."

    if user["username"] == session["username"]:
        connection.close()
        return "Du kannst deinen eigenen Benutzer nicht deaktivieren."

    new_status = 0 if user["is_active"] == 1 else 1

    connection.execute("""
        UPDATE users
        SET is_active = ?
        WHERE id = ?
    """, (new_status, user_id))

    connection.commit()
    connection.close()

    return redirect(url_for("users"))


@app.route("/add_patient", methods=["GET", "POST"])
def add_patient():
    if "username" not in session:
        return redirect(url_for("login"))

    if not has_permission(session["role"], "patients.manage"):
        abort(403)

    message = None

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        birthdate = request.form.get("birthdate", "").strip()
        bed_id = request.form.get("bed_id", type=int)
        admission_reason = request.form.get("admission_reason", "").strip()

        if not name or not birthdate or not admission_reason:
            return "Name, Geburtsdatum und Aufnahmegrund sind erforderlich.", 400

        connection = get_db_connection()
        bed = connection.execute("""
            SELECT beds.id, rooms.id AS room_id, rooms.station_id
            FROM beds
            JOIN rooms ON rooms.id = beds.room_id
            WHERE beds.id = ? AND beds.is_active = 1
              AND NOT EXISTS (
                  SELECT 1 FROM admissions
                  WHERE admissions.bed_id = beds.id
                    AND admissions.discharged_at IS NULL
              )
        """, (bed_id,)).fetchone()
        if not bed:
            connection.close()
            return "Das ausgewählte Bett ist nicht verfügbar.", 409

        try:
            cursor = connection.execute("""
                INSERT INTO patients (name, birthdate) VALUES (?, ?)
            """, (name, birthdate))
            patient_id = cursor.lastrowid
            connection.execute("""
                INSERT INTO admissions (
                    patient_id, station_id, room_id, bed_id,
                    admitted_by_user_id, admission_reason
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                patient_id, bed["station_id"], bed["room_id"], bed["id"],
                get_session_user_id(), admission_reason,
            ))
            connection.commit()
        except sqlite3.IntegrityError:
            connection.rollback()
            connection.close()
            return "Aufnahme fehlgeschlagen: Patient oder Bett ist bereits belegt.", 409
        connection.close()

        message = "Patient wurde erfolgreich aufgenommen."

    connection = get_db_connection()
    beds = connection.execute("""
        SELECT beds.id, beds.bed_label, rooms.room_number,
               stations.station_number
        FROM beds
        JOIN rooms ON rooms.id = beds.room_id
        JOIN stations ON stations.id = rooms.station_id
        WHERE beds.is_active = 1
          AND NOT EXISTS (
              SELECT 1 FROM admissions
              WHERE admissions.bed_id = beds.id
                AND admissions.discharged_at IS NULL
          )
        ORDER BY stations.station_number, rooms.room_number, beds.bed_label
    """).fetchall()
    connection.close()

    return render_template(
        "add_patient.html", message=message, beds=beds
    )


@app.route("/patient_location/<int:patient_id>", methods=["GET", "POST"])
def patient_location(patient_id):
    if "username" not in session:
        return redirect(url_for("login"))
    if not has_permission(session["role"], "patients.manage"):
        abort(403)

    connection = get_db_connection()
    patient = connection.execute("""
        SELECT patients.*, locations.admission_id, locations.station_id,
               locations.room_id, locations.bed_id, locations.station_number,
               locations.room_number, locations.bed_label, locations.admitted_at
        FROM patients
        LEFT JOIN current_patient_locations locations ON locations.patient_id = patients.id
        WHERE patients.id = ?
    """, (patient_id,)).fetchone()
    if not patient:
        connection.close()
        abort(404)

    message = None
    if request.method == "POST":
        action = request.form.get("action", "")
        reason = request.form.get("reason", "").strip()
        if not reason or len(reason) > 500:
            connection.close()
            return "Ein nachvollziehbarer Grund ist erforderlich.", 400
        bed = None

        if action in {"transfer", "admit"}:
            bed_id = request.form.get("bed_id", type=int)
            bed = connection.execute("""
                SELECT beds.id, rooms.id AS room_id, rooms.station_id
                FROM beds JOIN rooms ON rooms.id = beds.room_id
                WHERE beds.id = ? AND beds.is_active = 1
                  AND NOT EXISTS (
                      SELECT 1 FROM admissions
                      WHERE admissions.bed_id = beds.id
                        AND admissions.discharged_at IS NULL
                  )
            """, (bed_id,)).fetchone()
            if not bed:
                connection.close()
                return "Das ausgewählte Bett ist nicht verfügbar.", 409

        try:
            if action == "transfer" and patient["admission_id"]:
                connection.execute("""
                    INSERT INTO patient_transfers (
                        admission_id, patient_id,
                        from_station_id, from_room_id, from_bed_id,
                        to_station_id, to_room_id, to_bed_id,
                        transferred_by_user_id, transfer_reason
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    patient["admission_id"], patient_id,
                    patient["station_id"], patient["room_id"], patient["bed_id"],
                    bed["station_id"], bed["room_id"], bed["id"],
                    get_session_user_id(), reason,
                ))
                connection.execute("""
                    UPDATE admissions
                    SET station_id = ?, room_id = ?, bed_id = ?
                    WHERE id = ? AND discharged_at IS NULL
                """, (
                    bed["station_id"], bed["room_id"], bed["id"],
                    patient["admission_id"],
                ))
                message = "Patient wurde verlegt."
            elif action == "discharge" and patient["admission_id"]:
                connection.execute("""
                    UPDATE admissions
                    SET discharged_at = CURRENT_TIMESTAMP,
                        discharged_by_user_id = ?, discharge_reason = ?
                    WHERE id = ? AND discharged_at IS NULL
                """, (get_session_user_id(), reason, patient["admission_id"]))
                message = "Patient wurde entlassen."
            elif action == "admit" and not patient["admission_id"]:
                connection.execute("""
                    INSERT INTO admissions (
                        patient_id, station_id, room_id, bed_id,
                        admitted_by_user_id, admission_reason
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    patient_id, bed["station_id"], bed["room_id"], bed["id"],
                    get_session_user_id(), reason,
                ))
                message = "Patient wurde erneut aufgenommen."
            else:
                connection.close()
                return "Die Aktion passt nicht zum aktuellen Patientenstatus.", 409
            connection.commit()
        except sqlite3.IntegrityError:
            connection.rollback()
            connection.close()
            return "Die Aktion konnte wegen einer Belegungsüberschneidung nicht gespeichert werden.", 409

        log_access(
            session["username"], session["role"], patient_id,
            patient["name"], "Patientenbewegung", reason, action,
        )
        patient = connection.execute("""
            SELECT patients.*, locations.admission_id, locations.station_id,
                   locations.room_id, locations.bed_id, locations.station_number,
                   locations.room_number, locations.bed_label, locations.admitted_at
            FROM patients
            LEFT JOIN current_patient_locations locations ON locations.patient_id = patients.id
            WHERE patients.id = ?
        """, (patient_id,)).fetchone()

    beds = connection.execute("""
        SELECT beds.id, beds.bed_label, rooms.room_number,
               stations.station_number
        FROM beds
        JOIN rooms ON rooms.id = beds.room_id
        JOIN stations ON stations.id = rooms.station_id
        WHERE beds.is_active = 1
          AND NOT EXISTS (
              SELECT 1 FROM admissions
              WHERE admissions.bed_id = beds.id
                AND admissions.discharged_at IS NULL
          )
        ORDER BY stations.station_number, rooms.room_number, beds.bed_label
    """).fetchall()
    admissions = connection.execute("""
        SELECT admissions.*, stations.station_number, rooms.room_number,
               beds.bed_label, admitted_by.username AS admitted_by,
               discharged_by.username AS discharged_by
        FROM admissions
        JOIN stations ON stations.id = admissions.station_id
        JOIN rooms ON rooms.id = admissions.room_id
        JOIN beds ON beds.id = admissions.bed_id
        LEFT JOIN users admitted_by ON admitted_by.id = admissions.admitted_by_user_id
        LEFT JOIN users discharged_by ON discharged_by.id = admissions.discharged_by_user_id
        WHERE admissions.patient_id = ? ORDER BY admissions.admitted_at DESC
    """, (patient_id,)).fetchall()
    transfers = connection.execute("""
        SELECT patient_transfers.*, actor.username,
               fs.station_number AS from_station, fr.room_number AS from_room,
               fb.bed_label AS from_bed, ts.station_number AS to_station,
               tr.room_number AS to_room, tb.bed_label AS to_bed
        FROM patient_transfers
        JOIN users actor ON actor.id = patient_transfers.transferred_by_user_id
        JOIN stations fs ON fs.id = patient_transfers.from_station_id
        JOIN rooms fr ON fr.id = patient_transfers.from_room_id
        JOIN beds fb ON fb.id = patient_transfers.from_bed_id
        JOIN stations ts ON ts.id = patient_transfers.to_station_id
        JOIN rooms tr ON tr.id = patient_transfers.to_room_id
        JOIN beds tb ON tb.id = patient_transfers.to_bed_id
        WHERE patient_transfers.patient_id = ?
        ORDER BY patient_transfers.transferred_at DESC
    """, (patient_id,)).fetchall()
    connection.close()
    return render_template(
        "patient_location.html",
        patient=patient,
        beds=beds,
        admissions=admissions,
        transfers=transfers,
        message=message,
    )


@app.route("/patients/<int:patient_id>/nursing-note", methods=["GET", "POST"])
@app.route("/add_nursing_note/<int:patient_id>", methods=["GET", "POST"])
def add_nursing_note(patient_id):
    if "username" not in session:
        return redirect(url_for("login"))

    access_check = require_patient_access(patient_id)
    if access_check:
        return access_check

    if not has_permission(session["role"], "nursing_notes.create"):
        abort(403)

    connection = get_db_connection()

    patient = connection.execute("""
        SELECT * FROM patients WHERE id = ?
    """, (patient_id,)).fetchone()

    if patient is None:
        connection.close()
        return "Patient wurde nicht gefunden."

    if request.method == "GET":
        audit_patient_access(patient, "Pflegeeinträge")

    message = None

    if request.method == "POST":
        note_type = request.form["note_type"]
        note_text = request.form["note_text"]

        connection.execute("""
            INSERT INTO nursing_notes (patient_id, nurse_username, note_type, note_text)
            VALUES (?, ?, ?, ?)
        """, (patient_id, session["username"], note_type, note_text))

        connection.commit()
        audit_patient_access(patient, "Pflegeeinträge", "create")
        message = "Pflegeeintrag wurde gespeichert."

    connection.close()

    return render_template(
        "add_nursing_note.html",
        patient=patient,
        message=message
    )


@app.route("/patients/<int:patient_id>/doctor-order", methods=["GET", "POST"])
@app.route("/add_doctor_order/<int:patient_id>", methods=["GET", "POST"])
def add_doctor_order(patient_id):
    if "username" not in session:
        return redirect(url_for("login"))

    access_check = require_patient_access(patient_id)
    if access_check:
        return access_check

    if not has_permission(session["role"], "orders.create"):
        abort(403)

    connection = get_db_connection()

    patient = connection.execute("""
        SELECT * FROM patients WHERE id = ?
    """, (patient_id,)).fetchone()

    if patient is None:
        connection.close()
        return "Patient wurde nicht gefunden."

    if request.method == "GET":
        audit_patient_access(patient, "Ärztliche Anordnungen")

    message = None

    if request.method == "POST":
        order_text = request.form["order_text"]

        connection.execute("""
            INSERT INTO doctor_orders (patient_id, doctor_username, order_text)
            VALUES (?, ?, ?)
        """, (patient_id, session["username"], order_text))

        connection.commit()
        audit_patient_access(patient, "Ärztliche Anordnungen", "create")
        message = "Ärztliche Anordnung wurde gespeichert."

    connection.close()

    return render_template(
        "add_doctor_order.html",
        patient=patient,
        message=message
    )


@app.route("/patients/<int:patient_id>/curve", methods=["GET", "POST"])
@app.route("/patient_curve/<int:patient_id>", methods=["GET", "POST"])
def patient_curve(patient_id):
    if "username" not in session:
        return redirect(url_for("login"))

    access_check = require_patient_access(patient_id)
    if access_check:
        return access_check

    if not has_permission(session["role"], "vitals.view"):
        abort(403)

    selected_date = request.args.get("date")
    message = None

    connection = get_db_connection()

    patient = connection.execute("""
        SELECT * FROM patients WHERE id = ?
    """, (patient_id,)).fetchone()

    if patient is None:
        connection.close()
        return "Patient wurde nicht gefunden."

    if not selected_date:
        latest_vital_date = connection.execute("""
            SELECT MAX(record_date) AS latest_date
            FROM vital_signs
            WHERE patient_id = ?
        """, (patient_id,)).fetchone()
        selected_date = latest_vital_date["latest_date"] if latest_vital_date and latest_vital_date["latest_date"] else date.today().isoformat()

    if request.method == "GET":
        audit_patient_access(patient, "Patientenkurve")

    if request.method == "POST":
        if not has_permission(session["role"], "vitals.create"):
            abort(403)

        record_date = request.form["record_date"]
        record_time = request.form["record_time"]
        blood_pressure = request.form["blood_pressure"]
        pulse = request.form["pulse"]
        temperature = request.form["temperature"]
        oxygen_saturation = request.form["oxygen_saturation"]
        note = request.form["note"]

        connection.execute("""
            INSERT INTO vital_signs (
                patient_id,
                recorded_by,
                record_date,
                record_time,
                blood_pressure,
                pulse,
                temperature,
                oxygen_saturation,
                note
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            patient_id,
            session["username"],
            record_date,
            record_time,
            blood_pressure,
            pulse,
            temperature,
            oxygen_saturation,
            note
        ))

        connection.commit()
        audit_patient_access(patient, "Patientenkurve", "create")
        selected_date = record_date
        message = "Vitalwerte wurden gespeichert."

    vital_list = connection.execute("""
        SELECT * FROM vital_signs
        WHERE patient_id = ? AND record_date = ?
        ORDER BY record_time
    """, (patient_id, selected_date)).fetchall()

    connection.close()

    curve_rows = []
    pulse_values = []
    temperature_values = []
    spo2_values = []

    for vital in vital_list:
        status = "normal"
        alerts = []

        pulse = vital["pulse"]
        temperature = vital["temperature"]
        oxygen_saturation = vital["oxygen_saturation"]

        if pulse is not None and pulse != "":
            pulse = int(pulse)
            pulse_values.append(pulse)

            if pulse > 100:
                status = "auffällig"
                alerts.append("Puls erhöht")

        if temperature is not None and temperature != "":
            temperature = float(temperature)
            temperature_values.append(temperature)

            if temperature >= 38.0:
                status = "auffällig"
                alerts.append("Temperatur erhöht")

        if oxygen_saturation is not None and oxygen_saturation != "":
            oxygen_saturation = int(oxygen_saturation)
            spo2_values.append(oxygen_saturation)

            if oxygen_saturation < 94:
                status = "auffällig"
                alerts.append("SpO₂ niedrig")

        curve_rows.append({
            "data": vital,
            "status": status,
            "alerts": ", ".join(alerts) if alerts else "Keine Auffälligkeit"
        })

    abnormal_count = 0

    for row in curve_rows:
        if row["status"] == "auffällig":
            abnormal_count += 1

    summary = {
        "entries": len(curve_rows),
        "abnormal_count": abnormal_count,
        "max_pulse": max(pulse_values) if pulse_values else "-",
        "max_temperature": max(temperature_values) if temperature_values else "-",
        "min_spo2": min(spo2_values) if spo2_values else "-"
    }

    critical_count = 0
    for row in curve_rows:
        vital = row["data"]
        row["status_class"] = "stable" if row["status"] == "normal" else "warning"
        row["status_label"] = "Stabil" if row["status"] == "normal" else "Kontrolle"
        row["warning_score"] = 0 if row["status"] == "normal" else max(1, len(row["alerts"].split(",")))

        blood_pressure = vital["blood_pressure"] or ""
        row["systolic"] = "-"
        row["diastolic"] = "-"
        if "/" in blood_pressure:
            systolic_text, diastolic_text = blood_pressure.split("/", 1)
            try:
                row["systolic"] = int(systolic_text.strip())
                row["diastolic"] = int(diastolic_text.strip())
                if row["systolic"] >= 180 or row["systolic"] < 90:
                    row["status_class"] = "critical"
                    row["status_label"] = "Kritisch"
                    row["warning_score"] += 2
                    critical_count += 1
            except ValueError:
                pass

        if vital["oxygen_saturation"] is not None and vital["oxygen_saturation"] != "":
            if int(vital["oxygen_saturation"]) < 90 and row["status_class"] != "critical":
                row["status_class"] = "critical"
                row["status_label"] = "Kritisch"
                row["warning_score"] += 2
                critical_count += 1

    summary["critical_count"] = critical_count
    summary["overall_status"] = "Kritisch" if critical_count else ("Kontrolle nötig" if abnormal_count else "Stabil")

    chart_labels = []
    chart_pulse = []
    chart_temperature = []
    chart_spo2 = []

    for row in curve_rows:
        vital = row["data"]

        chart_labels.append(vital["record_time"])
        chart_pulse.append(vital["pulse"] if vital["pulse"] != "" else None)
        chart_temperature.append(vital["temperature"] if vital["temperature"] != "" else None)
        chart_spo2.append(vital["oxygen_saturation"] if vital["oxygen_saturation"] != "" else None)

    return render_template(
        "patient_curve.html",
        patient=patient,
        curve_rows=curve_rows,
        selected_date=selected_date,
        role=session["role"],
        message=message,
        summary=summary,
        chart_labels=chart_labels,
        chart_pulse=chart_pulse,
        chart_temperature=chart_temperature,
        chart_spo2=chart_spo2
    )


@app.route("/complete_order/<int:order_id>", methods=["POST"])
def complete_order(order_id):
    if "username" not in session:
        return redirect(url_for("login"))

    if not has_permission(session["role"], "orders.complete"):
        abort(403)

    connection = get_db_connection()

    order = connection.execute("""
        SELECT * FROM doctor_orders
        WHERE id = ?
    """, (order_id,)).fetchone()

    if order is None:
        connection.close()
        return "Anordnung wurde nicht gefunden."

    patient_id = order["patient_id"]

    access_check = require_patient_access(patient_id)
    if access_check:
        connection.close()
        return access_check

    connection.execute("""
        UPDATE doctor_orders
        SET status = 'erledigt',
            completed_by = ?,
            completed_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (session["username"], order_id))

    connection.commit()
    connection.close()

    patient_connection = get_db_connection()
    patient = patient_connection.execute(
        "SELECT * FROM patients WHERE id = ?", (patient_id,)
    ).fetchone()
    patient_connection.close()
    if patient:
        audit_patient_access(patient, "Ärztliche Anordnungen", "complete")

    return redirect(url_for("patient_detail", patient_id=patient_id))


@app.route("/add_order_from_curve/<int:patient_id>", methods=["POST"])
def add_order_from_curve(patient_id):
    if "username" not in session:
        return redirect(url_for("login"))

    access_check = require_patient_access(patient_id)
    if access_check:
        return access_check

    if not has_permission(session["role"], "orders.create"):
        abort(403)

    order_text = request.form["order_text"]

    connection = get_db_connection()

    patient = connection.execute("""
        SELECT * FROM patients WHERE id = ?
    """, (patient_id,)).fetchone()

    if patient is None:
        connection.close()
        return "Patient wurde nicht gefunden."

    connection.execute("""
        INSERT INTO doctor_orders (patient_id, doctor_username, order_text)
        VALUES (?, ?, ?)
    """, (patient_id, session["username"], order_text))

    connection.commit()
    connection.close()

    audit_patient_access(patient, "Ärztliche Anordnungen", "create")

    return redirect(url_for("patient_detail", patient_id=patient_id))


@app.route("/add_lab_request/<int:patient_id>", methods=["POST"])
def add_lab_request(patient_id):
    if "username" not in session:
        return redirect(url_for("login"))

    if not has_permission(session["role"], "lab_requests.create"):
        abort(403)

    access_check = require_patient_access(patient_id)
    if access_check:
        return access_check

    request_type = request.form.get("request_type", "Laborwert").strip()
    test_name = request.form.get("test_name", "").strip()
    priority = request.form.get("priority", "normal").strip()
    clinical_question = request.form.get("clinical_question", "").strip()

    if not test_name:
        return "Untersuchung ist erforderlich.", 400

    if request_type not in {"Laborwert", "Mikrobiologie", "Bildgebung", "Pathologie"}:
        return "Ungültige Anforderungsart.", 400

    if priority not in {"normal", "dringend", "kritisch"}:
        return "Ungültige Priorität.", 400

    connection = get_db_connection()
    patient = connection.execute(
        "SELECT * FROM patients WHERE id = ?", (patient_id,)
    ).fetchone()
    if not patient:
        connection.close()
        abort(404)

    connection.execute("""
        INSERT INTO lab_requests (
            patient_id,
            requested_by_user_id,
            request_type,
            test_name,
            priority,
            clinical_question
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        patient_id,
        get_session_user_id(),
        request_type,
        test_name,
        priority,
        clinical_question,
    ))

    connection.commit()
    connection.close()
    audit_patient_access(patient, "Laboranforderung", "create")
    return redirect(url_for("patient_detail", patient_id=patient_id))


@app.route("/notify_doctor/<int:patient_id>", methods=["POST"])
def notify_doctor(patient_id):
    if "username" not in session:
        return redirect(url_for("login"))

    access_check = require_patient_access(patient_id)
    if access_check:
        return access_check

    if not has_permission(session["role"], "notifications.create"):
        abort(403)

    message = request.form["message"]

    connection = get_db_connection()

    patient = connection.execute("""
        SELECT * FROM patients WHERE id = ?
    """, (patient_id,)).fetchone()

    if patient is None:
        connection.close()
        return "Patient wurde nicht gefunden."

    connection.execute("""
        INSERT INTO doctor_notifications (patient_id, sent_by, message)
        VALUES (?, ?, ?)
    """, (patient_id, session["username"], message))

    connection.commit()
    connection.close()

    audit_patient_access(patient, "Arztbenachrichtigung", "create")

    return redirect(url_for("patient_curve", patient_id=patient_id))


@app.route("/close_notification/<int:notification_id>", methods=["POST"])
def close_notification(notification_id):
    if "username" not in session:
        return redirect(url_for("login"))

    if not has_permission(session["role"], "notifications.manage"):
        abort(403)

    connection = get_db_connection()

    notification = connection.execute(
        "SELECT patient_id FROM doctor_notifications WHERE id = ?",
        (notification_id,),
    ).fetchone()
    if not notification:
        connection.close()
        abort(404)
    access_check = require_patient_access(notification["patient_id"])
    if access_check:
        connection.close()
        return access_check

    connection.execute("""
        UPDATE doctor_notifications
        SET status = 'geschlossen'
        WHERE id = ?
    """, (notification_id,))

    connection.commit()
    connection.close()

    return redirect(url_for("dashboard"))


@app.route("/patients/<int:patient_id>/medications")
@app.route("/medication_plan/<int:patient_id>")
def medication_plan(patient_id):
    if "username" not in session:
        return redirect(url_for("login"))

    access_check = require_patient_access(patient_id)
    if access_check:
        return access_check

    if not has_permission(session["role"], "medication.view"):
        abort(403)

    connection = get_db_connection()

    patient = connection.execute("""
        SELECT * FROM patients WHERE id = ?
    """, (patient_id,)).fetchone()

    if patient is None:
        connection.close()
        return "Patient wurde nicht gefunden."

    audit_patient_access(patient, "Medikationsplan")

    medications = connection.execute("""
        SELECT * FROM medication_plan
        WHERE patient_id = ?
        ORDER BY schedule_time
    """, (patient_id,)).fetchall()

    patient_warnings = connection.execute("""
        SELECT * FROM patient_warnings
        WHERE patient_id = ? AND is_active = 1
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'warning' THEN 2
                ELSE 3
            END,
            created_at DESC
    """, (patient_id,)).fetchall()

    connection.close()

    return render_template(
        "medication_plan.html",
        patient=patient,
        medications=medications,
        patient_warnings=patient_warnings,
        role=session["role"]
    )


@app.route("/add_medication/<int:patient_id>", methods=["GET", "POST"])
def add_medication(patient_id):
    if "username" not in session:
        return redirect(url_for("login"))

    access_check = require_patient_access(patient_id)
    if access_check:
        return access_check

    if not has_permission(session["role"], "medication.create"):
        abort(403)

    connection = get_db_connection()

    patient = connection.execute("""
        SELECT * FROM patients WHERE id = ?
    """, (patient_id,)).fetchone()

    if patient is None:
        connection.close()
        return "Patient wurde nicht gefunden."

    if request.method == "GET":
        audit_patient_access(patient, "Medikationsplan")

    message = None

    if request.method == "POST":
        medication_name = request.form.get("medication_name", "")
        dosage = request.form.get("dosage", "")
        schedule_time = request.form.get("schedule_time", "")
        instructions = request.form.get("instructions", "")

        if medication_name not in MEDICATION_CATALOG:
            connection.close()
            return "Ungültiges Medikament ausgewählt.", 400

        medication_info = MEDICATION_CATALOG[medication_name]
        full_instructions = (
            f"{instructions}\n\n"
            f"Wirkung/Kategorie: {medication_info['category']}\n"
            f"Beschreibung: {medication_info['description']}"
        )

        connection.execute("""
            INSERT INTO medication_plan (
                patient_id,
                medication_name,
                dosage,
                schedule_time,
                instructions,
                prescribed_by
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            patient_id,
            medication_name,
            dosage,
            schedule_time,
            full_instructions,
            session["username"]
        ))

        connection.commit()
        audit_patient_access(patient, "Medikationsplan", "create")
        message = "Medikation wurde gespeichert."

    connection.close()

    return render_template(
        "add_medication.html",
        patient=patient,
        message=message,
        medication_catalog=MEDICATION_CATALOG
    )


@app.route("/administer_medication/<int:medication_id>", methods=["POST"])
def administer_medication(medication_id):
    if "username" not in session:
        return redirect(url_for("login"))

    if not has_permission(session["role"], "medication.administer"):
        abort(403)

    connection = get_db_connection()

    medication = connection.execute("""
        SELECT * FROM medication_plan WHERE id = ?
    """, (medication_id,)).fetchone()

    if medication is None:
        connection.close()
        return "Medikation wurde nicht gefunden."

    patient_id = medication["patient_id"]

    access_check = require_patient_access(patient_id)
    if access_check:
        connection.close()
        return access_check

    connection.execute("""
        UPDATE medication_plan
        SET status = 'gegeben',
            administered_by = ?,
            administered_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (session["username"], medication_id))

    connection.commit()
    connection.close()

    patient_connection = get_db_connection()
    patient = patient_connection.execute(
        "SELECT * FROM patients WHERE id = ?", (patient_id,)
    ).fetchone()
    patient_connection.close()
    if patient:
        audit_patient_access(patient, "Medikationsplan", "administer")

    return redirect(url_for("medication_plan", patient_id=patient_id))


@app.route("/pause_medication/<int:medication_id>", methods=["POST"])
def pause_medication(medication_id):
    if "username" not in session:
        return redirect(url_for("login"))

    if not has_permission(session["role"], "medication.create"):
        abort(403)

    connection = get_db_connection()
    medication = connection.execute(
        "SELECT * FROM medication_plan WHERE id = ?", (medication_id,)
    ).fetchone()
    if not medication:
        connection.close()
        abort(404)

    access_check = require_patient_access(medication["patient_id"])
    if access_check:
        connection.close()
        return access_check

    connection.execute("""
        UPDATE medication_plan
        SET status = 'pausiert',
            paused_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (medication_id,))
    connection.commit()
    connection.close()
    return redirect(url_for("medication_plan", patient_id=medication["patient_id"]))


@app.route("/stop_medication/<int:medication_id>", methods=["POST"])
def stop_medication(medication_id):
    if "username" not in session:
        return redirect(url_for("login"))

    if not has_permission(session["role"], "medication.create"):
        abort(403)

    stop_reason = request.form.get("stop_reason", "").strip()
    connection = get_db_connection()
    medication = connection.execute(
        "SELECT * FROM medication_plan WHERE id = ?", (medication_id,)
    ).fetchone()
    if not medication:
        connection.close()
        abort(404)

    access_check = require_patient_access(medication["patient_id"])
    if access_check:
        connection.close()
        return access_check

    connection.execute("""
        UPDATE medication_plan
        SET status = 'abgesetzt',
            stopped_at = CURRENT_TIMESTAMP,
            stopped_by = ?,
            stop_reason = ?
        WHERE id = ?
    """, (session["username"], stop_reason, medication_id))
    connection.commit()
    connection.close()
    return redirect(url_for("medication_plan", patient_id=medication["patient_id"]))


@app.route("/nursing_tasks")
def nursing_tasks():
    if "username" not in session:
        return redirect(url_for("login"))

    if not (
        has_permission(session["role"], "orders.complete")
        and has_permission(session["role"], "medication.administer")
    ):
        abort(403)

    connection = get_db_connection()

    station_ids = get_accessible_station_ids()
    if station_ids:
        placeholders = ",".join("?" for _ in station_ids)
        open_orders = connection.execute(f"""
            SELECT doctor_orders.*, patients.name AS patient_name,
                   locations.station_number, locations.room_number,
                   locations.bed_label
            FROM doctor_orders
            JOIN patients ON doctor_orders.patient_id = patients.id
            JOIN current_patient_locations locations ON locations.patient_id = patients.id
            WHERE doctor_orders.status = 'offen'
              AND locations.station_id IN ({placeholders})
            ORDER BY doctor_orders.created_at DESC
        """, station_ids).fetchall()

        open_medications = connection.execute(f"""
            SELECT medication_plan.*, patients.name AS patient_name,
                   locations.station_number, locations.room_number,
                   locations.bed_label
            FROM medication_plan
            JOIN patients ON medication_plan.patient_id = patients.id
            JOIN current_patient_locations locations ON locations.patient_id = patients.id
            WHERE medication_plan.status = 'offen'
              AND locations.station_id IN ({placeholders})
            ORDER BY medication_plan.schedule_time
        """, station_ids).fetchall()
    else:
        open_orders = []
        open_medications = []

    connection.close()

    return render_template(
        "nursing_tasks.html",
        open_orders=open_orders,
        open_medications=open_medications
    )


@app.route("/patients/<int:patient_id>/lab-report", methods=["GET", "POST"])
@app.route("/add_lab_report/<int:patient_id>", methods=["GET", "POST"])
def add_lab_report(patient_id):
    if "username" not in session:
        return redirect(url_for("login"))

    if not has_permission(session["role"], "lab.create"):
        abort(403)

    access_check = require_patient_access(patient_id)
    if access_check:
        return access_check

    connection = get_db_connection()

    patient = connection.execute("""
        SELECT * FROM patients WHERE id = ?
    """, (patient_id,)).fetchone()

    if patient is None:
        connection.close()
        return "Patient wurde nicht gefunden."

    if request.method == "GET":
        audit_patient_access(patient, "Laborbefunde")

    message = None
    open_lab_requests = connection.execute("""
        SELECT lab_requests.*, users.username AS requested_by
        FROM lab_requests
        JOIN users ON users.id = lab_requests.requested_by_user_id
        WHERE lab_requests.patient_id = ?
          AND lab_requests.status IN ('offen', 'in Arbeit')
        ORDER BY
            CASE lab_requests.priority
                WHEN 'kritisch' THEN 1
                WHEN 'dringend' THEN 2
                ELSE 3
            END,
            lab_requests.created_at DESC
    """, (patient_id,)).fetchall()

    if request.method == "POST":
        lab_request_id = request.form.get("lab_request_id", type=int)
        report_type = request.form.get("report_type", "Laborwert").strip()
        test_name = request.form.get("test_name", "").strip()
        sample_material = request.form.get("sample_material", "").strip()
        result_value = request.form.get("result_value", "").strip()
        result_unit = request.form.get("result_unit", "").strip()
        reference_range = request.form.get("reference_range", "").strip()
        interpretation = request.form.get("interpretation", "").strip()
        collected_at = request.form.get("collected_at", "").strip()
        status = request.form.get("status", "final").strip()
        notes = request.form.get("notes", "").strip()
        file_description = request.form.get("file_description", "").strip()

        if not test_name or not result_value:
            connection.close()
            return "Untersuchung und Ergebnis sind Pflichtfelder.", 400

        if report_type not in {"Laborwert", "Mikrobiologie", "Bildgebung", "Pathologie", "Sonstiger Befund"}:
            connection.close()
            return "Ungültige Befundart.", 400

        if status not in {"angefordert", "vorläufig", "final", "kritisch"}:
            connection.close()
            return "Ungültiger Befundstatus.", 400

        cursor = connection.execute("""
            INSERT INTO lab_reports (
                patient_id,
                lab_username,
                report_type,
                test_name,
                sample_material,
                result_value,
                result_unit,
                reference_range,
                interpretation,
                collected_at,
                status,
                notes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            patient_id,
            session["username"],
            report_type,
            test_name,
            sample_material,
            result_value,
            result_unit,
            reference_range,
            interpretation,
            collected_at,
            status,
            notes
        ))

        lab_report_id = cursor.lastrowid
        uploaded_files = request.files.getlist("attachments")
        for uploaded_file in uploaded_files:
            if not uploaded_file or not uploaded_file.filename:
                continue
            saved_file = save_lab_file(uploaded_file)
            if not saved_file:
                connection.close()
                return "Nur PNG, JPG, JPEG, WEBP oder GIF Dateien sind erlaubt.", 400
            stored_filename, original_filename, extension = saved_file
            connection.execute("""
                INSERT INTO lab_report_files (
                    lab_report_id,
                    filename,
                    original_filename,
                    file_type,
                    description,
                    uploaded_by
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                lab_report_id,
                stored_filename,
                original_filename,
                extension,
                file_description,
                session["username"],
            ))

        if lab_request_id:
            connection.execute("""
                UPDATE lab_requests
                SET status = 'erledigt',
                    completed_at = CURRENT_TIMESTAMP,
                    completed_by = ?
                WHERE id = ? AND patient_id = ?
            """, (session["username"], lab_request_id, patient_id))

        if status == "kritisch":
            connection.execute("""
                INSERT INTO doctor_notifications (patient_id, sent_by, message)
                VALUES (?, ?, ?)
            """, (
                patient_id,
                session["username"],
                f"Kritischer Befund: {test_name} - {result_value} {result_unit}".strip(),
            ))

        connection.commit()
        audit_patient_access(patient, "Laborbefunde", "create")
        message = "Laborbefund wurde gespeichert."

    connection.close()

    return render_template(
        "add_lab_report.html",
        patient=patient,
        message=message,
        open_lab_requests=open_lab_requests,
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
