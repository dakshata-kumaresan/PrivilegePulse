import json
import streamlit as st
import pandas as pd
from pathlib import Path

# Page configuration
st.set_page_config(
    page_title="PrivilegePulse | Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Demo data location
DATA_FILE = Path("data/demo_cloudtrail_events.json")

# Load sanitized demo events
def load_demo_events():
    if not DATA_FILE.exists():
        st.error("Demo CloudTrail data file not found.")
        return []

    with open(DATA_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    return data.get("Records", [])

# Dashboard title
st.title("🛡️ PrivilegePulse")
st.caption("AWS IAM Privilege Escalation & Suspicious Activity Detection")
st.info("DEMO MODE — Uses sanitized sample CloudTrail events. No real-time monitoring or email alerts.")

# Load events
events = load_demo_events()

if events:
    st.success(f"Successfully loaded {len(events)} demo CloudTrail events.")
else:
    st.warning("No demo events available.")

    # IAM Risk Classification

HIGH_RISK_EVENTS = [
    "CreateAccessKey",
    "DeleteUser",
    "DeleteRole",
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


def classify_event(event):

    event_name = event.get("eventName", "")
    error_code = event.get("errorCode")

    if error_code:
        return "REVIEW", "FAILED"

    elif event_name in HIGH_RISK_EVENTS:
        return "HIGH", "NO ERROR RECORDED"

    elif event_name in MEDIUM_RISK_EVENTS:
        return "MEDIUM", "NO ERROR RECORDED"

    else:
        return "LOW", "NO ERROR RECORDED"


# Process demo events
for event in events:
    risk, status = classify_event(event)
    event["risk_level"] = risk
    event["event_status"] = status

    # Security Overview

st.divider()
st.header("📊 Security Overview")

# Calculate risk counts
total_events = len(events)

high_count = sum(
    1 for event in events
    if event["risk_level"] == "HIGH"
)

medium_count = sum(
    1 for event in events
    if event["risk_level"] == "MEDIUM"
)

review_count = sum(
    1 for event in events
    if event["risk_level"] == "REVIEW"
)

low_count = sum(
    1 for event in events
    if event["risk_level"] == "LOW"
)

# Display metrics
col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Total Events", total_events)
col2.metric("HIGH Risk", high_count)
col3.metric("MEDIUM Risk", medium_count)
col4.metric("REVIEW", review_count)
col5.metric("LOW Risk", low_count)

# Security Analytics

st.divider()
st.header("📈 Security Analytics")

col1, col2 = st.columns(2)

# Risk Distribution Chart
with col1:
    st.subheader("Risk Distribution")

    risk_data = pd.DataFrame({
        "Risk Level": ["HIGH", "MEDIUM", "REVIEW", "LOW"],
        "Count": [
            high_count,
            medium_count,
            review_count,
            low_count
        ]
    })

    st.bar_chart(
        risk_data,
        x="Risk Level",
        y="Count",
        color="#E76F51"
    )

# Event Distribution Chart
with col2:
    st.subheader("IAM Event Distribution")

    event_counts = pd.DataFrame(
        [
            {"Event": name, "Count": count}
            for name, count in
            pd.Series([
                event.get("eventName", "Unknown")
                for event in events
            ]).value_counts().items()
        ]
    )

    if not event_counts.empty:
        st.bar_chart(
            event_counts,
            x="Event",
            y="Count"
        )

        # Security Findings

st.divider()
st.header("🔍 Security Findings")

findings = []

for event in events:
    findings.append({
        "Event Name": event.get("eventName", "Unknown"),
        "User": event.get("userIdentity", {}).get(
            "userName", "Unknown"
        ),
        "Source IP": event.get("sourceIPAddress", "Unknown"),
        "Risk Level": event["risk_level"],
        "Event Status": event["event_status"],
        "Event Time": event.get("eventTime", "Unknown")
    })

findings_df = pd.DataFrame(findings)

# Risk level filter
selected_risk = st.multiselect(
    "Filter by Risk Level",
    ["HIGH", "MEDIUM", "REVIEW", "LOW"],
    default=["HIGH", "MEDIUM", "REVIEW", "LOW"]
)

filtered_findings = findings_df[
    findings_df["Risk Level"].isin(selected_risk)
]

st.dataframe(
    filtered_findings,
    use_container_width=True,
    hide_index=True
)

st.caption("Demo findings are generated from sanitized sample CloudTrail events.")

# Demo Incident Overview

st.divider()
st.header("🚨 Incident Overview")

incident_col1, incident_col2, incident_col3 = st.columns(3)

incident_col1.metric("Total Demo Incidents", total_events)
incident_col2.metric("Potential High-Risk Incidents", high_count)
incident_col3.metric("Events Requiring Review", review_count)

st.subheader("Incident Details")

incident_data = []

for event in events:
    if event["risk_level"] in ["HIGH", "MEDIUM", "REVIEW"]:
        incident_data.append({
            "Event ID": event.get("eventID", "DEMO"),
            "Event Name": event.get("eventName", "Unknown"),
            "Risk Level": event["risk_level"],
            "Status": event["event_status"],
            "Alert Status": "Demo Only - No Email Sent"
        })

if incident_data:
    incident_df = pd.DataFrame(incident_data)

    st.dataframe(
        incident_df,
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("No demo incidents found.")

st.divider()

st.caption(
    "PrivilegePulse | Demo Environment | "
    "Uses sanitized CloudTrail sample data | "
    "No real email alerts are sent."
)
