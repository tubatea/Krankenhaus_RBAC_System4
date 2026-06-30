import sqlite3
from werkzeug.security import generate_password_hash
from migrations import run_migrations


def create_database():
    connection = sqlite3.connect("hospital.db")  # verbindet Python mit der Datenbankdatei
    cursor = connection.cursor()  # schickt SQL-Befehle an die Datenbank

    # Aktiviert die Prüfung von Fremdschlüsseln in SQLite
    cursor.execute("PRAGMA foreign_keys = ON")

    # Organizational structure: this demo section contains wards 48 and 49.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS stations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        station_number TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS rooms (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        station_id INTEGER NOT NULL,
        room_number TEXT NOT NULL,
        UNIQUE (station_id, room_number),
        FOREIGN KEY (station_id) REFERENCES stations(id)
    )
    """)

    # Tabelle für Benutzer
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        is_active INTEGER DEFAULT 1
    )
    """)

    # Tabelle für Patienten
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS patients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        birthdate TEXT NOT NULL
    )
    """)

    # Tabelle für Zugriffsprotokolle
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        role TEXT NOT NULL,
        patient_id INTEGER,
        patient_name TEXT NOT NULL,
        accessed_data TEXT NOT NULL,
        access_reason TEXT NOT NULL,
        action TEXT NOT NULL DEFAULT 'view',
        access_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS failed_login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        ip_address TEXT,
        success INTEGER NOT NULL DEFAULT 0,
        reason TEXT,
        attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS account_lockouts (
        username TEXT PRIMARY KEY,
        failed_count INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS active_sessions (
        session_id TEXT PRIMARY KEY,
        user_id INTEGER,
        username TEXT NOT NULL,
        role TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        login_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        current_shift TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_type TEXT NOT NULL,
        username TEXT,
        role TEXT,
        patient_id INTEGER,
        message TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'warning',
        status TEXT NOT NULL DEFAULT 'open',
        metadata TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients(id)
    )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_failed_logins_username_time ON failed_login_attempts(username, attempted_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_active_sessions_seen ON active_sessions(is_active, last_seen_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_alerts_status_time ON security_alerts(status, created_at)")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_stations (
        user_id INTEGER NOT NULL,
        station_id INTEGER NOT NULL,
        PRIMARY KEY (user_id, station_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (station_id) REFERENCES stations(id) ON DELETE CASCADE
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS duty_shifts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        duty_date TEXT NOT NULL,
        shift_type TEXT NOT NULL CHECK (shift_type IN ('Tagdienst', 'Spätdienst', 'Nachtdienst')),
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (user_id, duty_date),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS handover_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL,
        author_user_id INTEGER NOT NULL,
        shift_type TEXT NOT NULL,
        note_text TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE,
        FOREIGN KEY (author_user_id) REFERENCES users(id)
    )
    """)

    # Add audit fields to databases created by older versions of the project.
    log_columns = {row[1] for row in cursor.execute("PRAGMA table_info(access_logs)")}
    if "patient_id" not in log_columns:
        cursor.execute("ALTER TABLE access_logs ADD COLUMN patient_id INTEGER")
    if "action" not in log_columns:
        cursor.execute("ALTER TABLE access_logs ADD COLUMN action TEXT NOT NULL DEFAULT 'view'")
    if "privacy_risk_score" not in log_columns:
        cursor.execute("ALTER TABLE access_logs ADD COLUMN privacy_risk_score INTEGER NOT NULL DEFAULT 0")
    if "privacy_risk_level" not in log_columns:
        cursor.execute("ALTER TABLE access_logs ADD COLUMN privacy_risk_level TEXT NOT NULL DEFAULT 'low'")
    if "privacy_risk_reasons" not in log_columns:
        cursor.execute("ALTER TABLE access_logs ADD COLUMN privacy_risk_reasons TEXT")

    patient_columns = {row[1] for row in cursor.execute("PRAGMA table_info(patients)")}
    if "privacy_level" not in patient_columns:
        cursor.execute("ALTER TABLE patients ADD COLUMN privacy_level TEXT NOT NULL DEFAULT 'normal'")
    if "privacy_note" not in patient_columns:
        cursor.execute("ALTER TABLE patients ADD COLUMN privacy_note TEXT")

    # Tabelle für Pflegeeinträge
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS nursing_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL,
        nurse_username TEXT NOT NULL,
        note_type TEXT NOT NULL,
        note_text TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients(id)
    )
    """)

    # Tabelle für ärztliche Anordnungen
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS doctor_orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL,
        doctor_username TEXT NOT NULL,
        order_text TEXT NOT NULL,
        status TEXT DEFAULT 'offen',
        completed_by TEXT,
        completed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients(id)
    )
    """)

    # Tabelle für Medikationsplan
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS medication_plan (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL,
        medication_name TEXT NOT NULL,
        dosage TEXT NOT NULL,
        schedule_time TEXT NOT NULL,
        instructions TEXT,
        prescribed_by TEXT NOT NULL,
        status TEXT DEFAULT 'offen',
        administered_by TEXT,
        administered_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients(id)
    )
    """)

    # Tabelle für Patientenkurve / Vitalwerte
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vital_signs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL,
        recorded_by TEXT NOT NULL,
        record_date TEXT NOT NULL,
        record_time TEXT NOT NULL,
        blood_pressure TEXT,
        pulse INTEGER,
        temperature REAL,
        oxygen_saturation INTEGER,
        note TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients(id)
    )
    """)

    # Tabelle für Arzt-Benachrichtigungen
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS doctor_notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL,
        sent_by TEXT NOT NULL,
        message TEXT NOT NULL,
        status TEXT DEFAULT 'offen',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients(id)
    )
    """)

    # Tabelle für Laborbefunde
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS lab_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL,
        lab_username TEXT NOT NULL,
        test_name TEXT NOT NULL,
        result_value TEXT NOT NULL,
        reference_range TEXT,
        interpretation TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients(id)
    )
    """)

    medication_columns = {row[1] for row in cursor.execute("PRAGMA table_info(medication_plan)")}
    for column_name, column_definition in {
        "medication_type": "TEXT NOT NULL DEFAULT 'Regelmedikation'",
        "paused_at": "TIMESTAMP",
        "stopped_at": "TIMESTAMP",
        "stopped_by": "TEXT",
        "stop_reason": "TEXT",
    }.items():
        if column_name not in medication_columns:
            cursor.execute(f"ALTER TABLE medication_plan ADD COLUMN {column_name} {column_definition}")

    lab_columns = {row[1] for row in cursor.execute("PRAGMA table_info(lab_reports)")}
    for column_name, column_definition in {
        "report_type": "TEXT NOT NULL DEFAULT 'Laborwert'",
        "sample_material": "TEXT",
        "result_unit": "TEXT",
        "collected_at": "TEXT",
        "status": "TEXT NOT NULL DEFAULT 'final'",
        "notes": "TEXT",
    }.items():
        if column_name not in lab_columns:
            cursor.execute(f"ALTER TABLE lab_reports ADD COLUMN {column_name} {column_definition}")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS lab_report_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        lab_report_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        original_filename TEXT NOT NULL,
        file_type TEXT NOT NULL,
        description TEXT,
        uploaded_by TEXT NOT NULL,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (lab_report_id) REFERENCES lab_reports(id) ON DELETE CASCADE
    )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_lab_files_report ON lab_report_files(lab_report_id)")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS lab_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL,
        requested_by_user_id INTEGER NOT NULL,
        request_type TEXT NOT NULL,
        test_name TEXT NOT NULL,
        priority TEXT NOT NULL DEFAULT 'normal',
        clinical_question TEXT,
        status TEXT NOT NULL DEFAULT 'offen',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP,
        completed_by TEXT,
        FOREIGN KEY (patient_id) REFERENCES patients(id),
        FOREIGN KEY (requested_by_user_id) REFERENCES users(id)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS patient_warnings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL,
        warning_type TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        severity TEXT NOT NULL DEFAULT 'info',
        created_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active INTEGER NOT NULL DEFAULT 1,
        FOREIGN KEY (patient_id) REFERENCES patients(id)
    )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_lab_requests_patient_status ON lab_requests(patient_id, status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_patient_warnings_active ON patient_warnings(patient_id, is_active)")

    # Testbenutzer einfügen, wenn noch keine Benutzer existieren
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]

    if user_count == 0:
        cursor.executemany("""
        INSERT OR IGNORE INTO users (username, password, role, is_active)
        VALUES (?, ?, ?, ?)
        """, [
            ("arzt", generate_password_hash("1234"), "assistenzarzt", 1),
            ("pflege", generate_password_hash("1234"), "nurse_48", 1),
            ("pflege49", generate_password_hash("1234"), "nurse_49", 1),
            ("labor", generate_password_hash("1234"), "lab", 1),
            ("admin", generate_password_hash("1234"), "admin", 1),
            ("oberarzt", generate_password_hash("1234"), "oberarzt", 1),
            ("chefarzt", generate_password_hash("1234"), "chefarzt", 1)
        ])

    cursor.execute("UPDATE users SET role = 'assistenzarzt' WHERE role = 'doctor'")
    cursor.execute("UPDATE users SET role = 'nurse_48' WHERE username = 'pflege' AND role = 'nurse'")

    for username, role in (
        ("arzt48", "assistenzarzt"),
        ("arzt49", "assistenzarzt"),
        ("oberarzt48", "oberarzt"),
        ("oberarzt49", "oberarzt"),
        ("oberarzt", "oberarzt"),
        ("chefarzt", "chefarzt"),
        ("pflege49", "nurse_49"),
    ):
        cursor.execute("""
            INSERT OR IGNORE INTO users (username, password, role, is_active)
            VALUES (?, ?, ?, 1)
        """, (username, generate_password_hash("1234"), role))

    # Transparently upgrade the original demo passwords without losing accounts.
    for user_id, stored_password in cursor.execute("SELECT id, password FROM users").fetchall():
        if not stored_password.startswith(("scrypt:", "pbkdf2:")):
            cursor.execute(
                "UPDATE users SET password = ? WHERE id = ?",
                (generate_password_hash(stored_password), user_id),
            )

    cursor.executemany("""
        INSERT OR IGNORE INTO stations (station_number, name) VALUES (?, ?)
    """, [("48", "Station 48"), ("49", "Station 49")])

    station_ids = {
        number: station_id
        for station_id, number in cursor.execute(
            "SELECT id, station_number FROM stations"
        ).fetchall()
    }

    for station_number, room_numbers in {
        "48": ("4801", "4802", "4803", "4804", "4805"),
        "49": ("4901", "4902", "4903", "4904", "4905"),
    }.items():
        cursor.executemany("""
            INSERT OR IGNORE INTO rooms (station_id, room_number) VALUES (?, ?)
        """, [(station_ids[station_number], room) for room in room_numbers])

    default_station_access = {
        "arzt": ("48",),
        "arzt48": ("48",),
        "arzt49": ("49",),
        "oberarzt": ("48",),
        "oberarzt48": ("48",),
        "oberarzt49": ("49",),
        "pflege": ("48",),
        "pflege49": ("49",),
        "labor": ("48", "49"),
    }
    for username, station_numbers in default_station_access.items():
        user = cursor.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user:
            cursor.executemany("""
                INSERT OR IGNORE INTO user_stations (user_id, station_id)
                VALUES (?, ?)
            """, [(user[0], station_ids[number]) for number in station_numbers])

    # Testpatienten einfügen, wenn noch keine Patienten existieren
    cursor.execute("SELECT COUNT(*) FROM patients")
    patient_count = cursor.fetchone()[0]

    if patient_count == 0:
        cursor.executemany("""
        INSERT INTO patients (name, birthdate)
        VALUES (?, ?)
        """, [
            ("Max Müller", "1975-04-12"),
            ("Anna Schmidt", "1988-09-03"),
            ("Peter Wagner", "1964-11-21"),
            ("Fatima El Mansouri", "1992-02-18"),
            ("Helga Bauer", "1948-07-30"),
            ("Jonas Schneider", "2001-05-09")
        ])
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vitals_patient_date ON vital_signs(patient_id, record_date)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_handover_patient ON handover_notes(patient_id, created_at)")

    # Testdaten für Pflegeeinträge einfügen
    cursor.execute("SELECT COUNT(*) FROM nursing_notes")
    nursing_count = cursor.fetchone()[0]

    if nursing_count == 0:
        cursor.executemany("""
        INSERT INTO nursing_notes (
            patient_id,
            nurse_username,
            note_type,
            note_text
        )
        VALUES (?, ?, ?, ?)
        """, [
            (
                1,
                "pflege",
                "Beobachtung",
                "Patient wirkt stabil und ist selbstständig mobil."
            ),
            (
                2,
                "pflege",
                "Beobachtung",
                "Patientin wirkt erschöpft und hat erhöhte Temperatur."
            )
        ])

    # Testdaten für ärztliche Anordnungen einfügen
    cursor.execute("SELECT COUNT(*) FROM doctor_orders")
    order_count = cursor.fetchone()[0]

    if order_count == 0:
        cursor.executemany("""
        INSERT INTO doctor_orders (
            patient_id,
            doctor_username,
            order_text,
            status
        )
        VALUES (?, ?, ?, ?)
        """, [
            (
                1,
                "arzt",
                "Blutzucker morgens und abends kontrollieren.",
                "offen"
            ),
            (
                2,
                "arzt",
                "Temperatur alle 4 Stunden kontrollieren.",
                "offen"
            )
        ])

    # Testdaten für Medikationsplan einfügen
    cursor.execute("SELECT COUNT(*) FROM medication_plan")
    medication_count = cursor.fetchone()[0]

    if medication_count == 0:
        cursor.executemany("""
        INSERT INTO medication_plan (
            patient_id,
            medication_name,
            dosage,
            schedule_time,
            instructions,
            prescribed_by,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, [
            (
                1,
                "Metformin",
                "500 mg",
                "08:00",
                "Nach dem Frühstück einnehmen.",
                "arzt",
                "offen"
            ),
            (
                2,
                "Antibiotikum",
                "1 Tablette",
                "12:00",
                "Mit Wasser einnehmen.",
                "arzt",
                "offen"
            )
        ])

    warning_count = cursor.execute("SELECT COUNT(*) FROM patient_warnings").fetchone()[0]
    if warning_count == 0:
        cursor.executemany("""
            INSERT INTO patient_warnings (
                patient_id, warning_type, title, description, severity, created_by
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, [
            (1, "Allergie", "Penicillin-Allergie", "Bei Antibiotika-Verordnung beachten.", "critical", "admin"),
            (2, "Isolation", "Infektverdacht", "Hygienemaßnahmen und Schutzkleidung beachten.", "warning", "pflege"),
            (5, "Sturzrisiko", "Erhöhtes Sturzrisiko", "Mobilisation nur mit Unterstützung.", "warning", "pflege"),
        ])

    # Testdaten für die Patientenkurve einfügen
    cursor.execute("SELECT COUNT(*) FROM vital_signs")
    vital_count = cursor.fetchone()[0]

    if vital_count == 0:
        cursor.executemany("""
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
        """, [
            (
                1,
                "pflege",
                "2026-04-27",
                "08:00",
                "130/85",
                76,
                36.8,
                98,
                "Patient hat gefrühstückt und wirkt stabil."
            ),
            (
                1,
                "pflege",
                "2026-04-27",
                "12:00",
                "145/90",
                88,
                37.4,
                96,
                "Patient klagt über leichte Kopfschmerzen."
            ),
            (
                1,
                "pflege",
                "2026-04-27",
                "18:00",
                "125/80",
                72,
                36.9,
                98,
                "Patient wirkt gebessert und mobilisiert selbstständig."
            ),
            (
                2,
                "pflege",
                "2026-04-27",
                "08:30",
                "135/85",
                92,
                37.8,
                95,
                "Patientin wirkt etwas erschöpft."
            ),
            (
                2,
                "pflege",
                "2026-04-27",
                "13:00",
                "150/95",
                112,
                38.3,
                92,
                "Patientin wirkt unruhig, erhöhte Temperatur und niedrige SpO₂."
            ),
            (
                2,
                "pflege",
                "2026-04-27",
                "19:00",
                "140/88",
                98,
                37.6,
                95,
                "Zustand nach Kontrolle stabiler."
            )
        ])

    # Testdaten für Arzt-Benachrichtigungen einfügen
    cursor.execute("SELECT COUNT(*) FROM doctor_notifications")
    notification_count = cursor.fetchone()[0]

    if notification_count == 0:
        cursor.executemany("""
        INSERT INTO doctor_notifications (
            patient_id,
            sent_by,
            message,
            status
        )
        VALUES (?, ?, ?, ?)
        """, [
            (
                2,
                "pflege",
                "Patientin Anna Schmidt hat erhöhte Temperatur und niedrige Sauerstoffsättigung.",
                "offen"
            )
        ])

    # Testdaten für Laborbefunde einfügen
    cursor.execute("SELECT COUNT(*) FROM lab_reports")
    lab_count = cursor.fetchone()[0]

    if lab_count == 0:
        cursor.executemany("""
        INSERT INTO lab_reports (
            patient_id,
            lab_username,
            test_name,
            result_value,
            reference_range,
            interpretation
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """, [
            (
                1,
                "labor",
                "HbA1c",
                "7.2 %",
                "unter 5.7 %",
                "Erhöht, passend zu Diabetes mellitus."
            ),
            (
                2,
                "labor",
                "CRP",
                "48 mg/l",
                "unter 5 mg/l",
                "Erhöht, Hinweis auf Entzündung."
            )
        ])

    # Änderungen speichern, dann ausstehende versionierte Migrationen anwenden.
    connection.commit()
    run_migrations(connection)

    # Seed structured demo diagnoses only when a fresh database has none.
    if cursor.execute("SELECT COUNT(*) FROM patient_diagnoses").fetchone()[0] == 0:
        cursor.executemany("""
            INSERT INTO patient_diagnoses (patient_id, diagnosis_text)
            VALUES (?, ?)
        """, [(1, "Diabetes Typ 2"), (2, "Pneumonie")])

    # Seed initial admissions in normalized lifecycle tables for a fresh demo DB.
    rooms = cursor.execute("SELECT id FROM rooms").fetchall()
    for (room_id,) in rooms:
        cursor.executemany("""
            INSERT OR IGNORE INTO beds (room_id, bed_label) VALUES (?, ?)
        """, ((room_id, "A"), (room_id, "B")))

    demo_locations = (
        (1, "48", "4801", "A"),
        (2, "49", "4901", "A"),
        (3, "48", "4801", "B"),
        (4, "48", "4802", "A"),
        (5, "49", "4901", "B"),
        (6, "49", "4902", "A"),
    )

    for patient_id, station_number, room_number, bed_label in demo_locations:
        if cursor.execute("""
            SELECT 1 FROM admissions
            WHERE patient_id = ? AND discharged_at IS NULL
        """, (patient_id,)).fetchone():
            continue

        location = cursor.execute("""
            SELECT stations.id, rooms.id, beds.id
            FROM stations
            JOIN rooms ON rooms.station_id = stations.id
            JOIN beds ON beds.room_id = rooms.id
            WHERE stations.station_number = ?
              AND rooms.room_number = ?
              AND beds.bed_label = ?
              AND NOT EXISTS (
                  SELECT 1 FROM admissions
                  WHERE admissions.bed_id = beds.id
                    AND admissions.discharged_at IS NULL
              )
        """, (station_number, room_number, bed_label)).fetchone()

        if location:
            cursor.execute("""
                INSERT INTO admissions (
                    patient_id, station_id, room_id, bed_id, admission_reason
                ) VALUES (?, ?, ?, ?, 'Demo-Aufnahme')
            """, (patient_id, location[0], location[1], location[2]))

    def get_user_id(username):
        row = cursor.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        return row[0] if row else None

    def ensure_patient(name, birthdate, privacy_level="normal", privacy_note=None):
        row = cursor.execute("""
            SELECT id FROM patients
            WHERE name = ? AND birthdate = ?
        """, (name, birthdate)).fetchone()
        if row:
            patient_id = row[0]
            cursor.execute("""
                UPDATE patients
                SET privacy_level = ?, privacy_note = ?
                WHERE id = ?
            """, (privacy_level, privacy_note, patient_id))
            return patient_id

        cursor.execute("""
            INSERT INTO patients (name, birthdate, privacy_level, privacy_note)
            VALUES (?, ?, ?, ?)
        """, (name, birthdate, privacy_level, privacy_note))
        return cursor.lastrowid

    def ensure_admission(patient_id, station_number, room_number, bed_label, reason):
        if cursor.execute("""
            SELECT 1 FROM admissions
            WHERE patient_id = ? AND discharged_at IS NULL
        """, (patient_id,)).fetchone():
            return

        location = cursor.execute("""
            SELECT stations.id, rooms.id, beds.id
            FROM stations
            JOIN rooms ON rooms.station_id = stations.id
            JOIN beds ON beds.room_id = rooms.id
            WHERE stations.station_number = ?
              AND rooms.room_number = ?
              AND beds.bed_label = ?
              AND NOT EXISTS (
                  SELECT 1 FROM admissions
                  WHERE admissions.bed_id = beds.id
                    AND admissions.discharged_at IS NULL
              )
        """, (station_number, room_number, bed_label)).fetchone()

        if location:
            cursor.execute("""
                INSERT INTO admissions (
                    patient_id, station_id, room_id, bed_id,
                    admitted_by_user_id, admission_reason
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (patient_id, location[0], location[1], location[2], get_user_id("admin"), reason))

    presentation_patients = [
        ("Lea Hoffmann", "1995-03-14", "48", "4802", "B", "Migräne mit neurologischer Abklärung", "normal", None),
        ("Karl Becker", "1956-12-02", "48", "4803", "A", "ACS-Ausschluss bei Thoraxschmerz", "normal", None),
        ("Miriam Yilmaz", "1979-08-22", "48", "4803", "B", "LWS-Schmerz mit sensibler Symptomatik", "normal", None),
        ("Noah Fischer", "2010-01-19", "48", "4804", "A", "Asthma-Exazerbation", "normal", None),
        ("Sofia Klein", "1939-06-06", "49", "4902", "B", "Sturzereignis und Delir-Risiko", "gesperrt", "Nur mit expliziter Begründung öffnen."),
        ("Dr. Viktor Stein", "1968-10-10", "49", "4903", "A", "VIP-Patient nach elektivem Eingriff", "vip", "Prominenter Patient - erhöhte Diskretion."),
        ("Amira Haddad", "1984-04-25", "49", "4903", "B", "Postoperative Überwachung", "normal", None),
        ("Thomas Brandt", "1971-09-17", "49", "4904", "A", "Pneumonie und Sauerstoffbedarf", "normal", None),
        ("Elena Rossi", "1999-11-03", "48", "4804", "B", "Abklärung Anämie", "normal", None),
        ("Günther Vogel", "1942-02-28", "49", "4904", "B", "Herzinsuffizienz dekompensiert", "normal", None),
    ]

    presentation_patient_ids = {}
    for name, birthdate, station, room, bed, reason, privacy_level, privacy_note in presentation_patients:
        patient_id = ensure_patient(name, birthdate, privacy_level, privacy_note)
        presentation_patient_ids[name] = patient_id
        ensure_admission(patient_id, station, room, bed, reason)

    diagnosis_rows = [
        (presentation_patient_ids["Lea Hoffmann"], "Migräne, neurologische Bildgebung unauffällig"),
        (presentation_patient_ids["Karl Becker"], "Thoraxschmerz, ACS-Ausschluss"),
        (presentation_patient_ids["Miriam Yilmaz"], "Lumbalgie mit radikulärer Symptomatik"),
        (presentation_patient_ids["Noah Fischer"], "Asthma bronchiale, Exazerbation"),
        (presentation_patient_ids["Sofia Klein"], "Z. n. Sturz, Delir-Risiko"),
        (presentation_patient_ids["Dr. Viktor Stein"], "Postoperative Überwachung nach elektivem Eingriff"),
        (presentation_patient_ids["Thomas Brandt"], "Pneumonie rechts basal"),
        (presentation_patient_ids["Günther Vogel"], "Dekompensierte Herzinsuffizienz"),
    ]
    for patient_id, diagnosis in diagnosis_rows:
        if not cursor.execute("""
            SELECT 1 FROM patient_diagnoses
            WHERE patient_id = ? AND diagnosis_text = ?
        """, (patient_id, diagnosis)).fetchone():
            cursor.execute("""
                INSERT INTO patient_diagnoses (
                    patient_id, diagnosis_text, diagnosed_by_user_id
                ) VALUES (?, ?, ?)
            """, (patient_id, diagnosis, get_user_id("arzt")))

    orders = [
        (presentation_patient_ids["Karl Becker"], "arzt", "Troponin-Verlauf 0/3h abnehmen und EKG wiederholen.", "offen"),
        (presentation_patient_ids["Thomas Brandt"], "oberarzt", "Sauerstoffgabe titrieren, Ziel-SpO2 94-98%.", "offen"),
        (presentation_patient_ids["Sofia Klein"], "arzt", "Sturzprophylaxe, Delir-Screening pro Schicht.", "offen"),
        (presentation_patient_ids["Günther Vogel"], "oberarzt", "Bilanzierung und tägliches Gewicht dokumentieren.", "offen"),
        (presentation_patient_ids["Noah Fischer"], "arzt", "Peak-Flow vor und nach Inhalation messen.", "erledigt"),
    ]
    for patient_id, doctor, text, status in orders:
        if not cursor.execute("""
            SELECT 1 FROM doctor_orders
            WHERE patient_id = ? AND order_text = ?
        """, (patient_id, text)).fetchone():
            cursor.execute("""
                INSERT INTO doctor_orders (
                    patient_id, doctor_username, order_text, status
                ) VALUES (?, ?, ?, ?)
            """, (patient_id, doctor, text, status))

    medications = [
        (presentation_patient_ids["Karl Becker"], "ASS", "100 mg", "08:00", "Nach ärztlicher Anordnung.", "arzt", "offen", "Regelmedikation"),
        (presentation_patient_ids["Thomas Brandt"], "Ceftriaxon", "2 g i.v.", "12:00", "Antibiose nach Plan.", "oberarzt", "offen", "Antibiotikum"),
        (presentation_patient_ids["Noah Fischer"], "Salbutamol", "2 Hübe", "bei Bedarf", "Bei Dyspnoe dokumentieren.", "arzt", "offen", "Bedarfsmedikation"),
        (presentation_patient_ids["Günther Vogel"], "Furosemid", "40 mg", "08:00", "Bilanz beachten.", "oberarzt", "offen", "Regelmedikation"),
        (presentation_patient_ids["Sofia Klein"], "Paracetamol", "500 mg", "18:00", "Bei Schmerzen nach NRS.", "arzt", "offen", "Bedarfsmedikation"),
    ]
    for patient_id, name, dosage, schedule, instructions, prescribed_by, status, medication_type in medications:
        if not cursor.execute("""
            SELECT 1 FROM medication_plan
            WHERE patient_id = ? AND medication_name = ? AND schedule_time = ?
        """, (patient_id, name, schedule)).fetchone():
            cursor.execute("""
                INSERT INTO medication_plan (
                    patient_id, medication_name, dosage, schedule_time,
                    instructions, prescribed_by, status, medication_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (patient_id, name, dosage, schedule, instructions, prescribed_by, status, medication_type))

    nursing_notes = [
        (presentation_patient_ids["Thomas Brandt"], "pflege49", "Atmung", "Patient benötigt 2 l O2 über Nasenbrille, Husten produktiv."),
        (presentation_patient_ids["Sofia Klein"], "pflege49", "Sicherheit", "Patientin nachts desorientiert, Klingel in Reichweite, Bett niedrig gestellt."),
        (presentation_patient_ids["Noah Fischer"], "pflege", "Atmung", "Nach Inhalation deutlich entspannter, spricht ganze Sätze."),
        (presentation_patient_ids["Günther Vogel"], "pflege49", "Bilanz", "Einfuhr/Ausfuhr begonnen, Knöchelödeme beidseits."),
        (presentation_patient_ids["Miriam Yilmaz"], "pflege", "Schmerz", "Schmerz NRS 6 bei Bewegung, Wärme als angenehm beschrieben."),
    ]
    for patient_id, nurse, note_type, note_text in nursing_notes:
        if not cursor.execute("""
            SELECT 1 FROM nursing_notes
            WHERE patient_id = ? AND note_text = ?
        """, (patient_id, note_text)).fetchone():
            cursor.execute("""
                INSERT INTO nursing_notes (
                    patient_id, nurse_username, note_type, note_text
                ) VALUES (?, ?, ?, ?)
            """, (patient_id, nurse, note_type, note_text))

    vital_rows = [
        (presentation_patient_ids["Karl Becker"], "pflege", "2026-06-30", "08:10", "155/92", 104, 36.9, 97, "Thoraxdruck, EKG geschrieben."),
        (presentation_patient_ids["Thomas Brandt"], "pflege49", "2026-06-30", "07:45", "138/82", 112, 38.7, 91, "Fieber, O2 gestartet."),
        (presentation_patient_ids["Sofia Klein"], "pflege49", "2026-06-30", "06:30", "148/76", 96, 37.2, 95, "Unruhig, zeitweise desorientiert."),
        (presentation_patient_ids["Noah Fischer"], "pflege", "2026-06-30", "09:20", "118/70", 122, 37.0, 93, "Dyspnoe vor Inhalation."),
        (presentation_patient_ids["Günther Vogel"], "pflege49", "2026-06-30", "08:00", "165/88", 101, 36.6, 92, "Belastungsdyspnoe, Ödeme."),
        (presentation_patient_ids["Lea Hoffmann"], "pflege", "2026-06-30", "10:00", "122/78", 78, 36.7, 99, "Nach MRT stabil zurück."),
    ]
    for row in vital_rows:
        if not cursor.execute("""
            SELECT 1 FROM vital_signs
            WHERE patient_id = ? AND record_date = ? AND record_time = ?
        """, (row[0], row[2], row[3])).fetchone():
            cursor.execute("""
                INSERT INTO vital_signs (
                    patient_id, recorded_by, record_date, record_time,
                    blood_pressure, pulse, temperature, oxygen_saturation, note
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, row)

    lab_reports = [
        (presentation_patient_ids["Lea Hoffmann"], "labor", "Bildgebung", "MRT Schädel", "unauffälliger intrakranieller Befund", "", "", "Keine Blutung, keine Raumforderung.", "2026-06-30 10:20", "final", "cMRT inklusive T1/T2/FLAIR.", "demo_mrt_schaedel.png", "MRT Schädel cMRT"),
        (presentation_patient_ids["Miriam Yilmaz"], "labor", "Bildgebung", "MRT LWS", "Bandscheibenprotrusion L4/5", "", "", "Degenerative Veränderungen ohne hochgradige Spinalkanalstenose.", "2026-06-30 11:10", "final", "MRT LWS sagittal/axial.", "demo_mrt_lws.png", "MRT LWS"),
        (presentation_patient_ids["Thomas Brandt"], "labor", "Bildgebung", "CT Thorax nativ", "Infiltrat rechts basal", "", "", "Vereinbar mit Pneumonie, keine Pleuraergüsse.", "2026-06-30 09:55", "kritisch", "CT Thorax mit 3D-Rekonstruktion.", "demo_ct_thorax.png", "CT Thorax"),
        (presentation_patient_ids["Karl Becker"], "labor", "Laborwert", "Troponin T", "18", "ng/l", "< 14 ng/l", "Leicht erhöht, Verlauf empfohlen.", "2026-06-30 08:45", "vorläufig", "Kontrolle nach 3 Stunden offen.", None, None),
        (presentation_patient_ids["Thomas Brandt"], "labor", "Laborwert", "CRP", "136", "mg/l", "< 5 mg/l", "Deutlich erhöht.", "2026-06-30 08:20", "kritisch", "Bitte ärztlich rückmelden.", None, None),
        (presentation_patient_ids["Elena Rossi"], "labor", "Laborwert", "Hämoglobin", "9.4", "g/dl", "12.0-16.0 g/dl", "Anämie.", "2026-06-30 07:50", "final", "Ferritin nachfordern.", None, None),
        (presentation_patient_ids["Günther Vogel"], "labor", "Laborwert", "NT-proBNP", "2860", "pg/ml", "< 450 pg/ml", "Passend zu kardialer Dekompensation.", "2026-06-30 08:35", "kritisch", "Klinische Korrelation empfohlen.", None, None),
    ]
    for patient_id, lab_user, report_type, test_name, result_value, unit, reference, interpretation, collected_at, status, notes, filename, description in lab_reports:
        report = cursor.execute("""
            SELECT id FROM lab_reports
            WHERE patient_id = ? AND test_name = ?
        """, (patient_id, test_name)).fetchone()
        if report:
            report_id = report[0]
        else:
            cursor.execute("""
                INSERT INTO lab_reports (
                    patient_id, lab_username, report_type, test_name,
                    result_value, result_unit, reference_range,
                    interpretation, collected_at, status, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (patient_id, lab_user, report_type, test_name, result_value, unit, reference, interpretation, collected_at, status, notes))
            report_id = cursor.lastrowid

        if filename and not cursor.execute("""
            SELECT 1 FROM lab_report_files
            WHERE lab_report_id = ? AND filename = ?
        """, (report_id, filename)).fetchone():
            cursor.execute("""
                INSERT INTO lab_report_files (
                    lab_report_id, filename, original_filename, file_type,
                    description, uploaded_by
                ) VALUES (?, ?, ?, 'png', ?, ?)
            """, (report_id, filename, filename, description, lab_user))

    handover_rows = [
        (presentation_patient_ids["Thomas Brandt"], get_user_id("pflege49"), "Tagdienst", "Fieber und O2-Bedarf beobachten, CT-Befund ärztlich rückgemeldet."),
        (presentation_patient_ids["Sofia Klein"], get_user_id("pflege49"), "Nachtdienst", "Delir-Gefahr: nachts engmaschig orientieren, Sturzprophylaxe aktiv."),
        (presentation_patient_ids["Karl Becker"], get_user_id("pflege"), "Tagdienst", "Troponin-Verlauf 11:45 Uhr nicht vergessen."),
        (presentation_patient_ids["Günther Vogel"], get_user_id("pflege49"), "Tagdienst", "Bilanzierung begonnen, bitte Gewicht morgen früh kontrollieren."),
    ]
    for patient_id, author_id, shift_type, note_text in handover_rows:
        if author_id and not cursor.execute("""
            SELECT 1 FROM handover_notes
            WHERE patient_id = ? AND note_text = ?
        """, (patient_id, note_text)).fetchone():
            cursor.execute("""
                INSERT INTO handover_notes (
                    patient_id, author_user_id, shift_type, note_text
                ) VALUES (?, ?, ?, ?)
            """, (patient_id, author_id, shift_type, note_text))

    notification_rows = [
        (presentation_patient_ids["Thomas Brandt"], "pflege49", "CT Thorax und CRP kritisch: bitte Therapie prüfen.", "offen"),
        (presentation_patient_ids["Günther Vogel"], "pflege49", "Zunehmende Dyspnoe bei Belastung und erhöhte NT-proBNP.", "offen"),
        (presentation_patient_ids["Karl Becker"], "pflege", "Troponin leicht erhöht, Verlauf steht noch aus.", "offen"),
    ]
    for patient_id, sent_by, message, status in notification_rows:
        if not cursor.execute("""
            SELECT 1 FROM doctor_notifications
            WHERE patient_id = ? AND message = ?
        """, (patient_id, message)).fetchone():
            cursor.execute("""
                INSERT INTO doctor_notifications (
                    patient_id, sent_by, message, status
                ) VALUES (?, ?, ?, ?)
            """, (patient_id, sent_by, message, status))
    

    connection.commit()
    connection.close()


if __name__ == "__main__":
    create_database()
    print("Datenbank wurde erstellt.")
