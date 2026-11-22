
import sqlite3
import json
from email_alert import send_alert

DATABASE_NAME = "privilegepulse.db"
JSON_FILE = "data/cloudtrail_events.json"

HIGH_RISK_EVENTS = [
    "DeleteRole",
    "DeleteUser",
    "CreateAccessKey",
    "PutUserPolicy",
    "PutRolePolicy",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion"
]

MEDIUM_RISK_EVENTS = [
    "DeleteRolePolicy",
    "DeleteUserPolicy",
    "DetachRolePolicy",
    "DetachUserPolicy"
]


def create_database():
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE,
            event_name TEXT,
            user_identity TEXT,
            source_ip TEXT,
            risk_level TEXT,
            event_status TEXT,
            event_time TEXT
        )
    """)

    # Check whether alert_sent column already exists
    cursor.execute("PRAGMA table_info(incidents)")
    columns = [column[1] for column in cursor.fetchall()]

    if "alert_sent" not in columns:
        cursor.execute("""
            ALTER TABLE incidents
            ADD COLUMN alert_sent INTEGER NOT NULL DEFAULT 0
        """)

        # Prevent old incidents from triggering email alerts
        cursor.execute("""
            UPDATE incidents
            SET alert_sent = 1
        """)

    connection.commit()
    connection.close()


def save_incidents():
    with open(JSON_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    events = data.get("Records", [])

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    saved = 0

    for event in events:
        name = event.get("eventName", "Unknown")

        if name not in HIGH_RISK_EVENTS + MEDIUM_RISK_EVENTS:
            continue

        identity = event.get("userIdentity", {})

        user = (
            identity.get("userName")
            or identity.get("principalId")
            or identity.get("arn")
            or identity.get("type")
            or "Unknown"
        )

        error = event.get("errorCode")

        if error:
            risk = "REVIEW"
            status = "FAILED"
        else:
            risk = (
                "HIGH" if name in HIGH_RISK_EVENTS
                else "MEDIUM"
            )
            status = "NO ERROR RECORDED"

        event_id = event.get("eventID")

        if not event_id:
            continue

        cursor.execute("""
            INSERT OR IGNORE INTO incidents
            (event_id, event_name, user_identity,
             source_ip, risk_level, event_status, event_time)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            event_id,
            name,
            user,
            event.get("sourceIPAddress", "Unknown"),
            risk,
            status,
            event.get("eventTime")
        ))

        if cursor.rowcount > 0:
            saved += 1

    connection.commit()

    print("Incident database updated successfully!")
    print("New incidents saved:", saved)

    # Find HIGH-risk incidents that still need email alerts
    cursor.execute("""
        SELECT id, event_name, user_identity, event_time
        FROM incidents
        WHERE risk_level = 'HIGH'
        AND alert_sent = 0
    """)

    pending_alerts = cursor.fetchall()
    connection.close()

    # Send email alerts
    for incident in pending_alerts:
        incident_id, event_name, user, event_time = incident

        print("Sending alert for:", event_name)

        success = send_alert(
            event_name=event_name,
            risk_level="HIGH",
            event_time=event_time,
            user=user
        )

        if success:
            connection = sqlite3.connect(DATABASE_NAME)
            cursor = connection.cursor()

            cursor.execute("""
                UPDATE incidents
                SET alert_sent = 1
                WHERE id = ?
            """, (incident_id,))

            connection.commit()
            connection.close()

            print("Alert marked as sent!")

        else:
            print("Alert not sent. It can be retried later.")


if __name__ == "__main__":
    create_database()
    save_incidents()
