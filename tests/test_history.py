"""2.6: hours each device was seen, and its history view."""

from datetime import datetime, timedelta
from unittest import mock

import app as app_module
import db
from tests.helpers import TempDatabaseTestCase

MAC = "aa:bb:cc:dd:ee:01"
DEVICE = {"ip": "192.168.1.10", "mac": MAC, "vendor": "TestVendor"}
NOW = datetime(2026, 11, 16, 21, 30)


def seen_at(when):
    with mock.patch.object(db, "datetime", wraps=datetime) as fake:
        fake.now.return_value = when
        db.save_device(DEVICE)


class PresenceTests(TempDatabaseTestCase):
    def test_one_row_per_hour_however_often_scanned(self):
        for minutes in (0, 10, 50):
            seen_at(NOW.replace(minute=0) + timedelta(minutes=minutes))
        seen_at(NOW - timedelta(days=1))
        h = db.get_history(MAC, days=14, now=NOW)
        self.assertEqual(len(h["days"]), 14)
        self.assertEqual(h["days"][-1]["date"], "2026-11-16")
        self.assertEqual(h["days"][-1]["hours"][21], 1)
        self.assertEqual(h["days"][-1]["online"], 1, "three scans in one hour are one hour")
        self.assertEqual(h["days"][-2]["hours"][21], 1)
        self.assertEqual((h["online_hours"], h["by_hour"][21]), (2, 2))
        self.assertEqual(h["events"][-1]["kind"], db.NEW_DEVICE)

    def test_days_are_capped_and_old_hours_pruned(self):
        seen_at(NOW - timedelta(days=40))
        seen_at(NOW)
        self.assertEqual(len(db.get_history(MAC, days=999, now=NOW)["days"]), db.PRESENCE_DAYS)
        db.prune_events(now=NOW)
        with db.get_connection() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM presence").fetchone()[0], 1)

    def test_forgetting_a_device_forgets_its_hours(self):
        seen_at(NOW)
        db.delete_device(MAC)
        self.assertEqual(db.get_history(MAC, now=NOW)["online_hours"], 0)

    def test_older_databases_get_the_table(self):
        with db.get_connection() as conn:
            conn.execute("DROP TABLE presence")
        db.create_tables()
        seen_at(NOW)
        self.assertEqual(db.get_history(MAC, now=NOW)["online_hours"], 1)


class HistoryApiTests(TempDatabaseTestCase):
    def setUp(self):
        super().setUp()
        self.client = app_module.create_app().test_client()

    def test_history_endpoint(self):
        db.save_device(DEVICE)
        r = self.client.get(f"/api/devices/{MAC.upper()}/history?days=7")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(len(body["days"]), 7)
        self.assertEqual(body["online_hours"], 1)

    def test_bad_input(self):
        self.assertEqual(self.client.get("/api/devices/nope/history").status_code, 400)
        self.assertEqual(self.client.get(f"/api/devices/{MAC}/history?days=x").status_code, 400)
