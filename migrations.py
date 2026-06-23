"""Small, versioned SQLite migrations for persistent application data."""


def migration_001_normalized_clinical_lifecycle(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS patient_diagnoses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            diagnosis_text TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'resolved')),
            diagnosed_by_user_id INTEGER,
            diagnosed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved_by_user_id INTEGER,
            resolved_at TIMESTAMP,
            resolution_note TEXT,
            FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE,
            FOREIGN KEY (diagnosed_by_user_id) REFERENCES users(id),
            FOREIGN KEY (resolved_by_user_id) REFERENCES users(id)
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS beds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id INTEGER NOT NULL,
            bed_label TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            UNIQUE (room_id, bed_label),
            FOREIGN KEY (room_id) REFERENCES rooms(id)
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS admissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            station_id INTEGER NOT NULL,
            room_id INTEGER NOT NULL,
            bed_id INTEGER NOT NULL,
            admitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            admitted_by_user_id INTEGER,
            admission_reason TEXT NOT NULL,
            discharged_at TIMESTAMP,
            discharged_by_user_id INTEGER,
            discharge_reason TEXT,
            FOREIGN KEY (patient_id) REFERENCES patients(id),
            FOREIGN KEY (station_id) REFERENCES stations(id),
            FOREIGN KEY (room_id) REFERENCES rooms(id),
            FOREIGN KEY (bed_id) REFERENCES beds(id),
            FOREIGN KEY (admitted_by_user_id) REFERENCES users(id),
            FOREIGN KEY (discharged_by_user_id) REFERENCES users(id)
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS patient_transfers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admission_id INTEGER NOT NULL,
            patient_id INTEGER NOT NULL,
            from_station_id INTEGER NOT NULL,
            from_room_id INTEGER NOT NULL,
            from_bed_id INTEGER NOT NULL,
            to_station_id INTEGER NOT NULL,
            to_room_id INTEGER NOT NULL,
            to_bed_id INTEGER NOT NULL,
            transferred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            transferred_by_user_id INTEGER NOT NULL,
            transfer_reason TEXT NOT NULL,
            FOREIGN KEY (admission_id) REFERENCES admissions(id),
            FOREIGN KEY (patient_id) REFERENCES patients(id),
            FOREIGN KEY (transferred_by_user_id) REFERENCES users(id)
        )
    """)

    connection.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_admission_per_patient
        ON admissions(patient_id) WHERE discharged_at IS NULL
    """)
    connection.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_patient_per_bed
        ON admissions(bed_id) WHERE discharged_at IS NULL
    """)
    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_diagnoses_patient_status
        ON patient_diagnoses(patient_id, status, diagnosed_at)
    """)

    rooms = connection.execute("SELECT id FROM rooms").fetchall()
    for (room_id,) in rooms:
        connection.executemany("""
            INSERT OR IGNORE INTO beds (room_id, bed_label) VALUES (?, ?)
        """, ((room_id, "A"), (room_id, "B")))

    patient_columns = {
        row[1] for row in connection.execute("PRAGMA table_info(patients)").fetchall()
    }
    legacy_columns = {"diagnosis", "station_id", "room_id"}
    if legacy_columns.issubset(patient_columns):
        patients = connection.execute("""
            SELECT id, diagnosis, station_id, room_id FROM patients
        """).fetchall()
    else:
        patients = [
            (row[0], None, None, None)
            for row in connection.execute("SELECT id FROM patients").fetchall()
        ]
    for patient_id, diagnosis, station_id, room_id in patients:
        if diagnosis and not connection.execute(
            "SELECT 1 FROM patient_diagnoses WHERE patient_id = ?",
            (patient_id,),
        ).fetchone():
            connection.execute("""
                INSERT INTO patient_diagnoses (patient_id, diagnosis_text)
                VALUES (?, ?)
            """, (patient_id, diagnosis))

        if station_id and room_id and not connection.execute("""
            SELECT 1 FROM admissions
            WHERE patient_id = ? AND discharged_at IS NULL
        """, (patient_id,)).fetchone():
            bed = connection.execute("""
                SELECT beds.id FROM beds
                WHERE beds.room_id = ? AND beds.is_active = 1
                  AND NOT EXISTS (
                      SELECT 1 FROM admissions
                      WHERE admissions.bed_id = beds.id
                        AND admissions.discharged_at IS NULL
                  )
                ORDER BY beds.bed_label LIMIT 1
            """, (room_id,)).fetchone()
            if bed:
                connection.execute("""
                    INSERT INTO admissions (
                        patient_id, station_id, room_id, bed_id, admission_reason
                    ) VALUES (?, ?, ?, ?, ?)
                """, (patient_id, station_id, room_id, bed[0], "Datenmigration"))

    connection.execute("DROP VIEW IF EXISTS current_patient_locations")
    connection.execute("""
        CREATE VIEW current_patient_locations AS
        SELECT
            admissions.id AS admission_id,
            admissions.patient_id,
            admissions.station_id,
            admissions.room_id,
            admissions.bed_id,
            admissions.admitted_at,
            admissions.admission_reason,
            stations.station_number,
            rooms.room_number,
            beds.bed_label
        FROM admissions
        JOIN stations ON stations.id = admissions.station_id
        JOIN rooms ON rooms.id = admissions.room_id
        JOIN beds ON beds.id = admissions.bed_id
        WHERE admissions.discharged_at IS NULL
    """)


def migration_002_remove_legacy_patient_columns(connection):
    connection.execute("DROP INDEX IF EXISTS idx_patients_station")
    patient_columns = {
        row[1] for row in connection.execute("PRAGMA table_info(patients)").fetchall()
    }
    for column in (
        "diagnosis", "medication", "lab_results", "vital_values",
        "station_id", "room_id",
    ):
        if column in patient_columns:
            connection.execute(f"ALTER TABLE patients DROP COLUMN {column}")


MIGRATIONS = (
    (1, "normalized clinical diagnoses and patient lifecycle", migration_001_normalized_clinical_lifecycle),
    (2, "remove duplicated legacy patient columns", migration_002_remove_legacy_patient_columns),
)


def run_migrations(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            description TEXT NOT NULL,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    applied = {
        row[0] for row in connection.execute(
            "SELECT version FROM schema_migrations"
        ).fetchall()
    }

    for version, description, migration in MIGRATIONS:
        if version in applied:
            continue
        try:
            migration(connection)
            connection.execute("""
                INSERT INTO schema_migrations (version, description)
                VALUES (?, ?)
            """, (version, description))
            connection.commit()
        except Exception:
            connection.rollback()
            raise
