
import json
from datetime import datetime, timezone
import database

SIMULATED_FILE = "data/simulated_cloudtrail_events.json"

# Create one simulated FAILED IAM event
simulated_event = {
    "eventVersion": "1.08",

    "userIdentity": {
        "type": "IAMUser",
        "userName": "simulation-user",
        "principalId": "SIMULATED-PRINCIPAL"
    },

    "eventTime": datetime.now(timezone.utc).isoformat(),

    "eventSource": "iam.amazonaws.com",

    "eventName": "CreateAccessKey",

    "awsRegion": "us-east-1",

    "sourceIPAddress": "203.0.113.10",

    "userAgent": "PrivilegePulse-Simulation",

    "eventID": "PRIVILEGEPULSE-SIM-003",

    # Simulate a failed IAM operation
    "errorCode": "AccessDenied",

    "errorMessage": "User is not authorized to perform this operation.",

    "requestParameters": {
        "userName": "simulation-user"
    }
}

# Save the simulated event separately
with open(SIMULATED_FILE, "w", encoding="utf-8") as file:
    json.dump(
        {"Records": [simulated_event]},
        file,
        indent=4
    )

# Tell database module to use simulation file
database.JSON_FILE = SIMULATED_FILE

# Process the simulated event
database.create_database()
database.save_incidents()

print("\nFailed IAM Event Simulation completed!")

