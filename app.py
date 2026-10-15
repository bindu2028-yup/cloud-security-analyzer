import pandas as pd
import streamlit as st
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import OneHotEncoder

st.set_page_config(page_title="Cloud Security Analyzer", page_icon="🛡️", layout="wide")

st.title("🛡️ Cloud Security Posture & IAM Privilege Analyzer")
st.write("Analyze cloud audit logs and identify potentially risky activity.")

# Load the audit log data
df = pd.read_csv("security_logs.csv")
df["timestamp"] = pd.to_datetime(df["timestamp"])

# Security overview
st.subheader("Security Overview")

col1, col2, col3 = st.columns(3)
col1.metric("Total Events", len(df))
col2.metric("Unique Users", df["user"].nunique())
col3.metric("Failed Events", (df["status"] == "Failed").sum())

# Rule-based detection
risky_actions = [
    "DeleteTrail",
    "AttachAdminPolicy",
    "CreateUser",
    "CreateAccessKey",
    "DeleteUser",
]

df["Risk Flag"] = df["action"].isin(risky_actions)

st.subheader("Potentially Risky Events")
st.dataframe(df[df["Risk Flag"]], use_container_width=True)

# Machine-learning anomaly detection
st.subheader("Machine Learning: Unusual Activity")

features = ["user", "source_ip", "action", "resource", "status", "location", "admin"]

# Convert categorical values into numbers
encoder = OneHotEncoder(handle_unknown="ignore")
X = encoder.fit_transform(df[features].astype(str))

# Train an Isolation Forest model
model = IsolationForest(n_estimators=100, contamination=0.2, random_state=42)

predictions = model.fit_predict(X)

# -1 means unusual; 1 means not flagged as unusual
df["ML Anomaly"] = predictions == -1

st.caption(
    "Experimental results from simulated data. " "An anomaly is not proof of an attack."
)

st.metric("Events Flagged by ML", int(df["ML Anomaly"].sum()))

st.dataframe(df[df["ML Anomaly"]], use_container_width=True)

# Activity chart
st.subheader("Cloud Activity by Action")
st.bar_chart(df["action"].value_counts())
