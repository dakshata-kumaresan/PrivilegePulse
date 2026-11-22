

import json

FILE_PATH = "data/cloudtrail_events.json"

with open(FILE_PATH, "r", encoding="utf-8") as file:
    data = json.load(file)

events = data.get("Records", [])

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

findings = []

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

    findings.append({
        "event": name,
        "user": user,
        "source": event.get("eventSource", "Unknown"),
        "source_ip": event.get("sourceIPAddress", "Unknown"),
        "risk": risk,
        "status": status,
        "time": event.get("eventTime")
    })

print("\nPRIVILEGEPULSE - IMPROVED DETECTION")
print("=" * 45)

print("Total events:", len(events))
print("Findings:", len(findings))

for item in findings:
    print("\nEvent:", item["event"])
    print("User/Identity:", item["user"])
    print("Source:", item["source"])
    print("Source IP/Hostname:", item["source_ip"])
    print("Risk:", item["risk"])
    print("Status:", item["status"])
    print("Time:", item["time"])
    print("-" * 35)
