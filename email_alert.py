
import os
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

# Load credentials securely
load_dotenv()

SMTP_EMAIL = os.getenv("SMTP_EMAIL")
SMTP_APP_PASSWORD = os.getenv("SMTP_APP_PASSWORD")
ALERT_EMAIL = os.getenv("ALERT_EMAIL")


def send_alert(event_name, risk_level, event_time, user):

    if not SMTP_EMAIL or not SMTP_APP_PASSWORD or not ALERT_EMAIL:
        print("Email credentials are missing. Check your .env file.")
        return False

    message = EmailMessage()

    message["Subject"] = f"PrivilegePulse Alert: {risk_level} Risk Activity"
    message["From"] = SMTP_EMAIL
    message["To"] = ALERT_EMAIL

    message.set_content(f"""
PRIVILEGEPULSE SECURITY ALERT

A monitored IAM activity has been detected.

Event: {event_name}
Risk Level: {risk_level}
User/Identity: {user}
Event Time: {event_time}

Please review this activity in your PrivilegePulse dashboard.

This is an automated security notification.
""")

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_APP_PASSWORD)
            server.send_message(message)

        print("Email alert sent successfully!")
        return True

    except Exception as error:
        print("Email sending failed:", error)
        return False


if __name__ == "__main__":
    send_alert(
        event_name="AttachRolePolicy",
        risk_level="HIGH",
        event_time="Test Event",
        user="PrivilegePulse Test"
    )
