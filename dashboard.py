
import sqlite3
import pandas as pd
import json
import streamlit as st
from collections import Counter

# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="PrivilegePulse | Security Operations",
    page_icon="🛡️",
    layout="wide"
)

# --------------------------------------------------
# CUSTOM SOC-STYLE DESIGN
# --------------------------------------------------

st.markdown("""
<style>
    .stApp {
        background-color: #0b1120;
        color: #e2e8f0;
    }

    [data-testid="stHeader"] {
        background-color: #0b1120;
    }

    [data-testid="stSidebar"] {
        background-color: #111827;
    }

    [data-testid="stMetric"] {
        background-color: #172235;
        border: 1px solid #26364d;
        padding: 18px;
        border-radius: 12px;
    }

    [data-testid="stMetricLabel"] {
        color: #94a3b8;
    }

    [data-testid="stMetricValue"] {
        color: #f8fafc;
    }

    h1, h2, h3 {
        color: #f8fafc !important;
    }

    p, label {
        color: #cbd5e1;
    }

    .main-title {
        font-size: 34px;
        font-weight: 800;
        color: #f8fafc;
    }

    .subtitle {
        color: #94a3b8;
        font-size: 15px;
    }

    .section-label {
        color: #38bdf8;
        font-weight: 700;
        font-size: 13px;
        letter-spacing: 1px;
    }

    div[data-testid="stDataFrame"] {
        border: 1px solid #26364d;
        border-radius: 10px;
    }

    hr {
        border-color: #26364d;
    }
</style>
""", unsafe_allow_html=True)


# --------------------------------------------------
# HEADER
# --------------------------------------------------

st.markdown(
    '<div class="main-title">🛡️ PrivilegePulse</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'AWS IAM Privilege Escalation & Suspicious Activity Detection'
    '</div>',
    unsafe_allow_html=True
)

st.markdown("")
st.markdown(
    '<div class="section-label">SECURITY OPERATIONS OVERVIEW</div>',
    unsafe_allow_html=True
)

st.divider()


# --------------------------------------------------
# RISK EVENT DEFINITIONS
# --------------------------------------------------

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


# --------------------------------------------------
# LOAD CLOUDTRAIL DATA
# --------------------------------------------------

@st.cache_data
def load_events():
    with open(
        "data/cloudtrail_events.json",
        "r",
        encoding="utf-8"
    ) as file:
        data = json.load(file)

    return data.get("Records", [])


events = load_events()


# --------------------------------------------------
# ANALYSE CLOUDTRAIL EVENTS
# --------------------------------------------------

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
            "HIGH"
            if name in HIGH_RISK_EVENTS
            else "MEDIUM"
        )

        status = "NO ERROR RECORDED"

    findings.append({
        "Event": name,
        "User / Identity": user,
        "Source IP / Host": event.get(
            "sourceIPAddress", "Unknown"
        ),
        "Risk": risk,
        "Status": status,
        "Time": event.get("eventTime", "Unknown")
    })


# --------------------------------------------------
# SECURITY METRICS
# --------------------------------------------------

high_count = sum(
    1 for item in findings if item["Risk"] == "HIGH"
)

medium_count = sum(
    1 for item in findings if item["Risk"] == "MEDIUM"
)

review_count = sum(
    1 for item in findings if item["Risk"] == "REVIEW"
)

st.subheader("Security Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total CloudTrail Events",
    f"{len(events):,}"
)

col2.metric(
    "HIGH Risk",
    high_count,
    delta="Critical attention",
    delta_color="inverse"
)

col3.metric(
    "MEDIUM Risk",
    medium_count
)

col4.metric(
    "Needs Review",
    review_count
)

st.divider()


# --------------------------------------------------
# SECURITY ANALYTICS
# --------------------------------------------------

st.subheader("Security Analytics")

chart_col1, chart_col2 = st.columns(2)

# EVENT DISTRIBUTION

with chart_col1:

    st.markdown("#### CloudTrail Event Distribution")

    event_counts = Counter(
        event.get("eventName", "Unknown")
        for event in events
    )

    top_events = event_counts.most_common(10)

    if top_events:

        event_chart = pd.DataFrame(
            top_events,
            columns=["Event", "Count"]
        )

        st.bar_chart(
            event_chart.set_index("Event"),
            height=300
        )

    else:
        st.info("No CloudTrail events available.")


# RISK DISTRIBUTION

with chart_col2:

    st.markdown("#### Risk Distribution")

    risk_chart = pd.DataFrame({
        "Risk Level": ["HIGH", "MEDIUM", "REVIEW"],
        "Incidents": [
            high_count,
            medium_count,
            review_count
        ]
    })

    st.bar_chart(
        risk_chart.set_index("Risk Level"),
        height=300
    )

st.divider()


# --------------------------------------------------
# SECURITY FINDINGS
# --------------------------------------------------

st.subheader("🚨 Security Findings")

if findings:

    risk_filter = st.selectbox(
        "Filter findings by risk",
        ["ALL", "HIGH", "MEDIUM", "REVIEW"],
        key="cloudtrail_risk_filter"
    )

    filtered_findings = findings.copy()

    if risk_filter != "ALL":

        filtered_findings = [
            item for item in findings
            if item["Risk"] == risk_filter
        ]

    findings_df = pd.DataFrame(filtered_findings)

    def highlight_risk(value):

        colors = {
            "HIGH": "background-color: #7f1d1d; color: #fecaca;",
            "MEDIUM": "background-color: #78350f; color: #fde68a;",
            "REVIEW": "background-color: #1e3a8a; color: #bfdbfe;"
        }

        return colors.get(value, "")

    styled_findings = findings_df.style.map(
        highlight_risk,
        subset=["Risk"]
    )

    st.dataframe(
        styled_findings,
        use_container_width=True,
        hide_index=True
    )

    st.caption(
        f"Displaying {len(filtered_findings)} of "
        f"{len(findings)} monitored IAM findings."
    )

else:

    st.success("No monitored IAM activities found.")


st.divider()


# --------------------------------------------------
# DATABASE INCIDENT HISTORY
# --------------------------------------------------

st.subheader("🗄️ Incident Management")


def load_incidents():

    connection = sqlite3.connect("privilegepulse.db")

    query = """
        SELECT
            id,
            event_name,
            user_identity,
            source_ip,
            risk_level,
            event_status,
            event_time,
            alert_sent
        FROM incidents
        ORDER BY id DESC
    """

    try:
        df = pd.read_sql_query(query, connection)
    finally:
        connection.close()

    return df


incident_data = load_incidents()

total = len(incident_data)


# --------------------------------------------------
# INCIDENT OVERVIEW
# --------------------------------------------------

if total > 0:

    high = (
        incident_data["risk_level"] == "HIGH"
    ).sum()

    medium = (
        incident_data["risk_level"] == "MEDIUM"
    ).sum()

    review = (
        incident_data["risk_level"] == "REVIEW"
    ).sum()

    alerts_sent = (
        incident_data["alert_sent"] == 1
    ).sum()

    pending = (
        incident_data["alert_sent"] == 0
    ).sum()

    not_sent = (
        incident_data["alert_sent"] == 2
    ).sum()

    st.markdown("#### Incident Overview")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Incidents", total)

    col2.metric("HIGH Risk Incidents", high)

    col3.metric("MEDIUM Risk Incidents", medium)

    col4.metric("Emails Sent", alerts_sent)

    st.markdown(
        f"""
        **Additional Alert Information**

        - REVIEW incidents: {review}
        - Pending alerts: {pending}
        - Not sent (existing incidents): {not_sent}
        """
    )

    st.divider()


    # --------------------------------------------------
    # INCIDENT FILTERS
    # --------------------------------------------------

    st.markdown("#### Incident Records")

    filter_col1, filter_col2 = st.columns(2)

    with filter_col1:

        incident_risk_filter = st.selectbox(
            "Filter by Risk",
            ["ALL", "HIGH", "MEDIUM", "REVIEW"],
            key="incident_risk_filter"
        )

    with filter_col2:

        event_options = ["ALL"] + sorted(
            incident_data["event_name"]
            .dropna()
            .unique()
            .tolist()
        )

        event_filter = st.selectbox(
            "Filter by Event",
            event_options,
            key="incident_event_filter"
        )


    filtered_data = incident_data.copy()

    if incident_risk_filter != "ALL":

        filtered_data = filtered_data[
            filtered_data["risk_level"]
            == incident_risk_filter
        ]

    if event_filter != "ALL":

        filtered_data = filtered_data[
            filtered_data["event_name"] == event_filter
        ]


    # --------------------------------------------------
    # EMAIL ALERT STATUS
    # --------------------------------------------------

    filtered_data["Email Alert"] = (
        filtered_data["alert_sent"].map({
            1: "Sent",
            0: "Pending",
            2: "Not sent (existing)"
        }).fillna("Unknown")
    )

    filtered_data = filtered_data.drop(
        columns=["alert_sent"]
    )


    # --------------------------------------------------
    # RENAME COLUMNS
    # --------------------------------------------------

    filtered_data = filtered_data.rename(
        columns={
            "id": "Incident ID",
            "event_name": "Event",
            "user_identity": "User / Identity",
            "source_ip": "Source IP / Host",
            "risk_level": "Risk",
            "event_status": "Event Status",
            "event_time": "Event Time"
        }
    )


    # --------------------------------------------------
    # DISPLAY INCIDENT TABLE
    # --------------------------------------------------

    styled_incidents = filtered_data.style.map(
        highlight_risk,
        subset=["Risk"]
    )

    st.dataframe(
        styled_incidents,
        use_container_width=True,
        hide_index=True
    )

    st.caption(
        f"Showing {len(filtered_data)} of "
        f"{total} stored incidents."
    )

else:

    st.info("No incidents stored yet.")


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.caption(
    "🛡️ PrivilegePulse | AWS IAM Security Analytics"
)

st.caption(
    "Log analysis is based on manually exported CloudTrail "
    "events. Risk classifications are preliminary indicators "
    "and require further investigation."
)
