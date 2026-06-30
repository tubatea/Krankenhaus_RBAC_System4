import html.parser
import unittest
from urllib.parse import urlparse

import app as hospital_app


class LinkParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self.links.add(attrs["href"])
        if tag == "form" and attrs.get("action"):
            self.links.add(attrs["action"])


class NavigationSmokeTests(unittest.TestCase):
    def setUp(self):
        hospital_app.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = hospital_app.app.test_client()

    def login_as(self, username, role, user_id):
        with self.client.session_transaction() as session:
            session.clear()
            session["username"] = username
            session["role"] = role
            session["user_id"] = user_id
            session["csrf_token"] = "test-token"
            for patient_id in range(1, 20):
                session[f"patient_access_{patient_id}"] = {
                    "reason": "Behandlung" if role in hospital_app.DOCTOR_ROLES else "Pflege",
                    "granted_at": 9999999999,
                }

    def collect_links(self, url):
        response = self.client.get(url)
        self.assertLess(response.status_code, 500, url)
        parser = LinkParser()
        parser.feed(response.get_data(as_text=True))
        return response.status_code, parser.links

    def safe_get(self, href):
        if not href or href.startswith("#") or href.startswith("javascript:"):
            return
        parsed = urlparse(href)
        if parsed.scheme or parsed.netloc:
            return
        if href.startswith("/logout"):
            return
        response = self.client.get(href)
        self.assertLess(response.status_code, 500, href)

    def test_visible_links_do_not_crash_for_main_roles(self):
        roles = [
            ("admin", "admin", 4, ["/dashboard", "/patients", "/users", "/security", "/historical_patients"]),
            ("arzt", "assistenzarzt", 1, ["/dashboard", "/patients", "/patient/1", "/patient_curve/1", "/doctor_drafts"]),
            ("pflege", "nurse_48", 2, ["/dashboard", "/patients", "/patient/1", "/patient_curve/1", "/handover"]),
            ("pflege49", "nurse_49", 7, ["/dashboard", "/patients", "/patient/2", "/patient_curve/2", "/handover"]),
            ("labor", "lab", 3, ["/dashboard", "/patients"]),
        ]

        for username, role, user_id, start_urls in roles:
            with self.subTest(role=role):
                self.login_as(username, role, user_id)
                seen_links = set()
                for url in start_urls:
                    _, links = self.collect_links(url)
                    seen_links.update(links)
                for href in sorted(seen_links):
                    self.safe_get(href)

