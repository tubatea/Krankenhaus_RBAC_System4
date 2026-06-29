import time
import unittest
import re
import io
import os
import shutil
import sqlite3
import tempfile
from datetime import date
from pathlib import Path
from unittest.mock import patch

import app as hospital_app


class PermissionTests(unittest.TestCase):
    def test_admin_has_no_implicit_clinical_access(self):
        self.assertTrue(hospital_app.has_permission("admin", "users.manage"))
        self.assertTrue(hospital_app.has_permission("admin", "logs.view"))
        self.assertFalse(hospital_app.has_permission("admin", "diagnosis.view"))
        self.assertFalse(hospital_app.has_permission("admin", "medication.view"))
        self.assertFalse(hospital_app.has_permission("admin", "lab.view"))

    def test_clinical_write_permissions_are_separated(self):
        self.assertTrue(hospital_app.has_permission("assistenzarzt", "medication.create"))
        self.assertFalse(hospital_app.has_permission("nurse_48", "medication.create"))
        self.assertTrue(hospital_app.has_permission("nurse_48", "vitals.create"))
        self.assertFalse(hospital_app.has_permission("assistenzarzt", "vitals.create"))
        self.assertTrue(hospital_app.has_permission("lab", "lab.create"))
        self.assertFalse(hospital_app.has_permission("assistenzarzt", "lab.create"))

    def test_all_doctor_grades_receive_clinical_permissions(self):
        for role in ("assistenzarzt", "oberarzt", "chefarzt"):
            with self.subTest(role=role):
                self.assertTrue(hospital_app.has_permission(role, "orders.create"))
                self.assertTrue(hospital_app.has_permission(role, "handover.view"))


class WardAccessTests(unittest.TestCase):
    def setUp(self):
        hospital_app.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = hospital_app.app.test_client()

    def test_assistant_doctor_only_sees_assigned_ward(self):
        with self.client.session_transaction() as session:
            session["username"] = "arzt"
            session["role"] = "assistenzarzt"
            session["user_id"] = 1
        response = self.client.get("/patients")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"Anna Schmidt", response.data)
        self.assertIn(b"Station:</strong> 48", response.data)

    def test_chief_doctor_sees_both_wards(self):
        with self.client.session_transaction() as session:
            session["username"] = "chefarzt"
            session["role"] = "chefarzt"
            session["user_id"] = 6
        response = self.client.get("/patients")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Anna Schmidt", response.data)
        self.assertIn(b"Station:</strong> 48", response.data)
        self.assertIn(b"Station:</strong> 49", response.data)

    def test_station_nurses_only_see_their_own_ward(self):
        with self.client.session_transaction() as session:
            session["username"] = "pflege"
            session["role"] = "nurse_48"
            session["user_id"] = 2
        response = self.client.get("/patients")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Station:</strong> 48", response.data)
        self.assertNotIn(b"Station:</strong> 49", response.data)

        with self.client.session_transaction() as session:
            session["username"] = "pflege49"
            session["role"] = "nurse_49"
            session["user_id"] = 7
        response = self.client.get("/patients")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Station:</strong> 49", response.data)
        self.assertNotIn(b"Station:</strong> 48", response.data)

    def test_handover_shows_automatic_abnormal_vital_alert(self):
        connection = hospital_app.get_db_connection()
        station_49 = connection.execute(
            "SELECT id FROM stations WHERE station_number = '49'"
        ).fetchone()["id"]
        connection.close()
        with self.client.session_transaction() as session:
            session["username"] = "pflege"
            session["role"] = "nurse_49"
            session["user_id"] = 2
            session[f"handover_access_{station_49}"] = {
                "reason": "Übergabe",
                "granted_at": time.time(),
            }
        response = self.client.get(f"/handover?station_id={station_49}")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Auffällige Vitalwerte".encode(), response.data)


    def test_station_nurse_can_unlock_handover(self):
        connection = hospital_app.get_db_connection()
        station_48 = connection.execute(
            "SELECT id FROM stations WHERE station_number = '48'"
        ).fetchone()["id"]
        connection.close()

        with self.client.session_transaction() as session:
            session["username"] = "pflege"
            session["role"] = "nurse_48"
            session["user_id"] = 2
            session["csrf_token"] = "test-token"

        response = self.client.post(
            "/handover/unlock",
            data={
                "station_id": str(station_48),
                "access_reason": "Übergabe",
                "csrf_token": "test-token",
            },
        )
        self.assertEqual(response.status_code, 302)

        response = self.client.get(f"/handover?station_id={station_48}")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Letzte".encode(), response.data)


class PatientLifecycleTests(unittest.TestCase):
    def setUp(self):
        hospital_app.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = os.path.join(self.temp_dir.name, "hospital-test.db")
        shutil.copy2("hospital.db", self.database_path)

        def test_connection():
            connection = sqlite3.connect(self.database_path)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            return connection

        self.connection_patch = patch.object(
            hospital_app, "get_db_connection", side_effect=test_connection
        )
        self.connection_patch.start()
        self.client = hospital_app.app.test_client()

    def tearDown(self):
        self.connection_patch.stop()
        self.temp_dir.cleanup()

    def login_admin(self):
        with self.client.session_transaction() as session:
            session["username"] = "admin"
            session["role"] = "admin"
            session["user_id"] = 4
            session["csrf_token"] = "test-token"

    def test_transfer_is_historic_and_occupied_bed_is_rejected(self):
        self.login_admin()
        connection = hospital_app.get_db_connection()
        free_bed = connection.execute("""
            SELECT beds.id FROM beds
            WHERE NOT EXISTS (
                SELECT 1 FROM admissions
                WHERE admissions.bed_id = beds.id
                  AND admissions.discharged_at IS NULL
            ) ORDER BY beds.id LIMIT 1
        """).fetchone()["id"]
        occupied_bed = connection.execute("""
            SELECT bed_id FROM current_patient_locations WHERE patient_id = 2
        """).fetchone()["bed_id"]
        connection.close()

        response = self.client.post(
            "/patient_location/1",
            data={
                "action": "transfer", "bed_id": str(free_bed),
                "reason": "Stationswechsel", "csrf_token": "test-token",
            },
        )
        self.assertEqual(response.status_code, 200)
        connection = hospital_app.get_db_connection()
        self.assertEqual(
            connection.execute("""
                SELECT bed_id FROM current_patient_locations WHERE patient_id = 1
            """).fetchone()["bed_id"],
            free_bed,
        )
        self.assertEqual(
            connection.execute(
                "SELECT COUNT(*) FROM patient_transfers WHERE patient_id = 1"
            ).fetchone()[0],
            1,
        )
        connection.close()

        conflict = self.client.post(
            "/patient_location/1",
            data={
                "action": "transfer", "bed_id": str(occupied_bed),
                "reason": "Konflikttest", "csrf_token": "test-token",
            },
        )
        self.assertEqual(conflict.status_code, 409)

    def test_discharge_and_readmission_keep_admission_history(self):
        self.login_admin()
        response = self.client.post(
            "/patient_location/1",
            data={
                "action": "discharge", "reason": "Behandlung beendet",
                "csrf_token": "test-token",
            },
        )
        self.assertEqual(response.status_code, 200)
        connection = hospital_app.get_db_connection()
        self.assertIsNone(connection.execute(
            "SELECT * FROM current_patient_locations WHERE patient_id = 1"
        ).fetchone())
        bed_id = connection.execute("""
            SELECT id FROM beds WHERE NOT EXISTS (
                SELECT 1 FROM admissions
                WHERE admissions.bed_id = beds.id
                  AND admissions.discharged_at IS NULL
            ) ORDER BY id LIMIT 1
        """).fetchone()["id"]
        connection.close()

        response = self.client.post(
            "/patient_location/1",
            data={
                "action": "admit", "bed_id": str(bed_id),
                "reason": "Wiederaufnahme", "csrf_token": "test-token",
            },
        )
        self.assertEqual(response.status_code, 200)
        connection = hospital_app.get_db_connection()
        self.assertEqual(connection.execute(
            "SELECT COUNT(*) FROM admissions WHERE patient_id = 1"
        ).fetchone()[0], 2)
        connection.close()

    def test_doctor_adds_structured_diagnosis(self):
        with self.client.session_transaction() as session:
            session["username"] = "arzt"
            session["role"] = "assistenzarzt"
            session["user_id"] = 1
            session["csrf_token"] = "test-token"
            session["patient_access_1"] = {
                "reason": "Behandlung", "granted_at": time.time(),
            }
        response = self.client.post(
            "/add_diagnosis/1",
            data={"diagnosis_text": "Testdiagnose", "csrf_token": "test-token"},
        )
        self.assertEqual(response.status_code, 302)
        connection = hospital_app.get_db_connection()
        diagnosis = connection.execute("""
            SELECT * FROM patient_diagnoses
            WHERE patient_id = 1 AND diagnosis_text = 'Testdiagnose'
        """).fetchone()
        connection.close()
        self.assertIsNotNone(diagnosis)

    def test_nurse_can_set_today_shift(self):
        with self.client.session_transaction() as session:
            session["username"] = "pflege"
            session["role"] = "nurse_48"
            session["user_id"] = 2
            session["csrf_token"] = "test-token"
        response = self.client.post(
            "/set_shift",
            data={"shift_type": "Nachtdienst", "csrf_token": "test-token"},
        )
        self.assertEqual(response.status_code, 302)
        connection = hospital_app.get_db_connection()
        shift = connection.execute("""
            SELECT shift_type FROM duty_shifts
            WHERE user_id = 2 AND duty_date = ?
        """, (date.today().isoformat(),)).fetchone()
        self.assertEqual(shift["shift_type"], "Nachtdienst")
        connection.execute(
            "DELETE FROM duty_shifts WHERE user_id = 2 AND duty_date = ?",
            (date.today().isoformat(),),
        )
        connection.commit()
        connection.close()

    def test_lab_can_create_advanced_report_with_image(self):
        upload_dir = Path(self.temp_dir.name) / "lab_uploads"
        with patch.object(hospital_app, "LAB_UPLOAD_FOLDER", upload_dir):
            with self.client.session_transaction() as session:
                session["username"] = "labor"
                session["role"] = "lab"
                session["user_id"] = 3
                session["csrf_token"] = "test-token"
                session["patient_access_1"] = {
                    "reason": "Laboruntersuchung",
                    "granted_at": time.time(),
                }

            response = self.client.post(
                "/add_lab_report/1",
                data={
                    "csrf_token": "test-token",
                    "report_type": "Bildgebung",
                    "status": "final",
                    "test_name": "CT Thorax",
                    "sample_material": "CT",
                    "result_value": "Infiltrat rechts basal",
                    "result_unit": "",
                    "reference_range": "",
                    "interpretation": "Bildgebung passend zu Pneumonie.",
                    "notes": "Bild wurde angehängt.",
                    "file_description": "CT Screenshot",
                    "attachments": (io.BytesIO(b"\x89PNG\r\n\x1a\n"), "ct_scan.png"),
                },
                content_type="multipart/form-data",
            )

        self.assertEqual(response.status_code, 200)
        connection = hospital_app.get_db_connection()
        report = connection.execute("""
            SELECT * FROM lab_reports
            WHERE patient_id = 1 AND test_name = 'CT Thorax'
            ORDER BY id DESC
        """).fetchone()
        self.assertIsNotNone(report)
        file_row = connection.execute("""
            SELECT * FROM lab_report_files
            WHERE lab_report_id = ?
        """, (report["id"],)).fetchone()
        connection.close()
        self.assertIsNotNone(file_row)
        self.assertEqual(file_row["original_filename"], "ct_scan.png")

    def test_doctor_can_request_lab_and_critical_result_notifies_doctor(self):
        with self.client.session_transaction() as session:
            session["username"] = "arzt"
            session["role"] = "assistenzarzt"
            session["user_id"] = 1
            session["csrf_token"] = "test-token"
            session["patient_access_1"] = {
                "reason": "Behandlung",
                "granted_at": time.time(),
            }

        response = self.client.post(
            "/add_lab_request/1",
            data={
                "csrf_token": "test-token",
                "request_type": "Laborwert",
                "test_name": "Troponin",
                "priority": "kritisch",
                "clinical_question": "ACS ausschließen",
            },
        )
        self.assertEqual(response.status_code, 302)

        connection = hospital_app.get_db_connection()
        lab_request = connection.execute("""
            SELECT * FROM lab_requests
            WHERE patient_id = 1 AND test_name = 'Troponin'
            ORDER BY id DESC
        """).fetchone()
        connection.close()
        self.assertIsNotNone(lab_request)

        with self.client.session_transaction() as session:
            session["username"] = "labor"
            session["role"] = "lab"
            session["user_id"] = 3
            session["csrf_token"] = "test-token"
            session["patient_access_1"] = {
                "reason": "Laboruntersuchung",
                "granted_at": time.time(),
            }

        response = self.client.post(
            "/add_lab_report/1",
            data={
                "csrf_token": "test-token",
                "lab_request_id": str(lab_request["id"]),
                "report_type": "Laborwert",
                "status": "kritisch",
                "test_name": "Troponin",
                "sample_material": "Serum",
                "result_value": "1200",
                "result_unit": "ng/l",
                "reference_range": "< 14 ng/l",
                "interpretation": "kritisch erhöht",
                "notes": "telefonisch gemeldet",
            },
        )
        self.assertEqual(response.status_code, 200)

        connection = hospital_app.get_db_connection()
        updated_request = connection.execute(
            "SELECT status FROM lab_requests WHERE id = ?", (lab_request["id"],)
        ).fetchone()
        notification = connection.execute("""
            SELECT * FROM doctor_notifications
            WHERE patient_id = 1 AND message LIKE '%Kritischer Befund%'
            ORDER BY id DESC
        """).fetchone()
        connection.close()
        self.assertEqual(updated_request["status"], "erledigt")
        self.assertIsNotNone(notification)

    def test_doctor_can_pause_and_stop_medication(self):
        with self.client.session_transaction() as session:
            session["username"] = "arzt"
            session["role"] = "assistenzarzt"
            session["user_id"] = 1
            session["csrf_token"] = "test-token"
            session["patient_access_1"] = {
                "reason": "Behandlung",
                "granted_at": time.time(),
            }

        connection = hospital_app.get_db_connection()
        medication = connection.execute("""
            SELECT * FROM medication_plan
            WHERE patient_id = 1 AND status = 'offen'
            ORDER BY id LIMIT 1
        """).fetchone()
        connection.close()
        self.assertIsNotNone(medication)

        response = self.client.post(
            f"/pause_medication/{medication['id']}",
            data={"csrf_token": "test-token"},
        )
        self.assertEqual(response.status_code, 302)

        connection = hospital_app.get_db_connection()
        paused = connection.execute(
            "SELECT status FROM medication_plan WHERE id = ?", (medication["id"],)
        ).fetchone()
        connection.execute(
            "UPDATE medication_plan SET status = 'offen', paused_at = NULL WHERE id = ?",
            (medication["id"],),
        )
        connection.commit()
        connection.close()
        self.assertEqual(paused["status"], "pausiert")

        response = self.client.post(
            f"/stop_medication/{medication['id']}",
            data={"csrf_token": "test-token", "stop_reason": "Nebenwirkung"},
        )
        self.assertEqual(response.status_code, 302)

        connection = hospital_app.get_db_connection()
        stopped = connection.execute(
            "SELECT status, stop_reason FROM medication_plan WHERE id = ?",
            (medication["id"],),
        ).fetchone()
        connection.execute(
            "UPDATE medication_plan SET status = 'offen', stopped_at = NULL, stopped_by = NULL, stop_reason = NULL WHERE id = ?",
            (medication["id"],),
        )
        connection.commit()
        connection.close()
        self.assertEqual(stopped["status"], "abgesetzt")
        self.assertEqual(stopped["stop_reason"], "Nebenwirkung")


class PatientGrantTests(unittest.TestCase):
    def setUp(self):
        hospital_app.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = hospital_app.app.test_client()

    def test_valid_grant_unlocks_patient(self):
        with self.client.session_transaction() as session:
            session["patient_access_1"] = {
                "reason": "Behandlung",
                "granted_at": time.time(),
            }

        with self.client.session_transaction() as session:
            with hospital_app.app.test_request_context():
                for key, value in session.items():
                    hospital_app.session[key] = value
                hospital_app.session["role"] = "assistenzarzt"
                self.assertTrue(hospital_app.has_unlocked_patient_access(1))

    def test_expired_grant_is_rejected(self):
        with hospital_app.app.test_request_context():
            hospital_app.session["patient_access_1"] = {
                "reason": "Behandlung",
                "granted_at": time.time() - hospital_app.PATIENT_ACCESS_TTL_SECONDS - 1,
            }
            self.assertFalse(hospital_app.has_unlocked_patient_access(1))


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        hospital_app.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = hospital_app.app.test_client()

    def csrf_token(self, path="/login"):
        response = self.client.get(path)
        match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(match)
        return match.group(1).decode()

    def test_post_without_csrf_token_is_rejected(self):
        response = self.client.post(
            "/login", data={"username": "arzt", "password": "1234"}
        )
        self.assertEqual(response.status_code, 400)

    def test_hashed_demo_password_can_log_in(self):
        token = self.csrf_token()
        response = self.client.post(
            "/login",
            data={"username": "arzt", "password": "1234", "csrf_token": token},
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/choose_shift"))

    def test_admin_cannot_open_patient_curve(self):
        with self.client.session_transaction() as session:
            session["username"] = "admin"
            session["role"] = "admin"
            session["patient_access_1"] = {
                "reason": "Administrative Prüfung",
                "granted_at": time.time(),
            }
        response = self.client.get("/patient_curve/1")
        self.assertEqual(response.status_code, 403)

    def test_patient_detail_hides_medical_sections_until_access_reason(self):
        with self.client.session_transaction() as session:
            session["username"] = "arzt"
            session["role"] = "assistenzarzt"
            session["user_id"] = 1

        response = self.client.get("/patient/1")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Zugriff freischalten".encode(), response.data)
        self.assertNotIn(b"Metformin", response.data)

        with self.client.session_transaction() as session:
            session["patient_access_1"] = {
                "reason": "Behandlung",
                "granted_at": time.time(),
            }

        response = self.client.get("/patient/1")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Metformin", response.data)

    def test_clinical_roles_do_not_see_patient_access_log_section(self):
        with self.client.session_transaction() as session:
            session["username"] = "arzt"
            session["role"] = "assistenzarzt"
            session["user_id"] = 1
            session["patient_access_1"] = {
                "reason": "Behandlung",
                "granted_at": time.time(),
            }

        response = self.client.get("/patient/1")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Zugriffsprotokoll".encode(), response.data)

    def test_admin_can_see_patient_access_log_section(self):
        with self.client.session_transaction() as session:
            session["username"] = "admin"
            session["role"] = "admin"
            session["user_id"] = 4
            session["patient_access_1"] = {
                "reason": "Administrative Prüfung",
                "granted_at": time.time(),
            }

        response = self.client.get("/patient/1")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Zugriffsprotokoll".encode(), response.data)

    def test_patient_curve_page_renders_for_doctor(self):
        with self.client.session_transaction() as session:
            session["username"] = "arzt"
            session["role"] = "assistenzarzt"
            session["user_id"] = 1
            session["patient_access_1"] = {
                "reason": "Behandlung",
                "granted_at": time.time(),
            }

        response = self.client.get("/patient_curve/1")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Tagesübersicht".encode(), response.data)

    def test_doctor_drafts_page_renders(self):
        with self.client.session_transaction() as session:
            session["username"] = "arzt"
            session["role"] = "assistenzarzt"
            session["user_id"] = 1

        response = self.client.get("/doctor_drafts")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Arztbrief".encode(), response.data)

    def test_doctor_cannot_create_lab_report(self):
        with self.client.session_transaction() as session:
            session["username"] = "arzt"
            session["role"] = "assistenzarzt"
            session["user_id"] = 1
            session["patient_access_1"] = {
                "reason": "Behandlung",
                "granted_at": time.time(),
            }
        response = self.client.get("/add_lab_report/1")
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
