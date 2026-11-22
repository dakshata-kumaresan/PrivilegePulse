
import json
from collections import Counter

file_path = "data/cloudtrail_events.json"

with open(file_path, "r", encoding="utf-8") as file:
    cloudtrail_data = json.load(file)

events = cloudtrail_data.get("Records", [])

print("PRIVILEGEPULSE - EVENT ANALYSIS")
print("=" * 40)

print("Total events:", len(events))

# Count event types
event_counts = Counter(
    event.get("eventName", "Unknown")
    for event in events
)

print("\nEVENT FREQUENCY")
print("-" * 40)

for name, count in event_counts.most_common():
    print(f"{name}: {count}")

# Identify important IAM activities
important_events = [
    "DeleteRole",
    "DeleteUser",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "CreateAccessKey",
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion"
]

print("\nIMPORTANT IAM ACTIVITIES")
print("-" * 40)

for event in events:
    name = event.get("eventName")

    if name in important_events:
        print(
            name,
            "| Time:", event.get("eventTime"),
            "| Error:", event.get("errorCode", "None")
        )
