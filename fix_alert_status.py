
import sqlite3

connection = sqlite3.connect("privilegepulse.db")
cursor = connection.cursor()

# Keep the simulated incident that actually sent an email
# Mark older incidents as intentionally not emailed
cursor.execute("""
    UPDATE incidents
    SET alert_sent = 2
    WHERE event_id != 'PRIVILEGEPULSE-SIM-001'
""")

connection.commit()
connection.close()

print("Email alert statuses corrected successfully!")
