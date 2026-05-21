import os
import time
import streamlit as st
import requests
import pandas as pd
import plotly.express as px

st.set_page_config(page_title="DevOps SIEM Engine", layout="wide")
st.title("🛡️ Reactive DevSecOps Outlier Detection Dashboard")
st.markdown("---")

# Target backend telemetry service
BACKEND_METRICS_URL = "http://ml-engine:8000/metrics"
metrics_placeholder = st.empty()

while True:
    with metrics_placeholder.container():
        try:
            res = requests.get(BACKEND_METRICS_URL, timeout=1)
            lines = res.text.split("\n")
            
            total_logs, blocked_ips, anomaly_events = 0, 0, 0
            
            for line in lines:
                if "siem_processed_logs_total" in line and "status=" in line:
                    val = line.split(" ")[1]
                    total_logs += int(float(val))
                elif "siem_active_blocked_ips_count" in line and not line.startswith("#"):
                    blocked_ips = int(float(line.split(" ")[1]))
                elif "siem_anomalies_detected_total" in line and not line.startswith("#"):
                    anomaly_events = int(float(line.split(" ")[1]))

            # UI Cards Row
            col1, col2, col3 = st.columns(3)
            col1.metric(label="📊 Total Ingested Traffic Packets", value=total_logs)
            col2.metric(label="🚨 ML Outlier Events Captured", value=anomaly_events)
            col3.metric(label="🚫 Actively Banned Attacker IPs", value=blocked_ips)

            st.markdown("### 📈 Pipeline Operational Analytics")
            chart_col, state_col = st.columns([2, 1])
            
            with chart_col:
                chart_data = pd.DataFrame({
                    "Classification Metric": ["Safe Traffic Stream", "Mitigated Attack Vectors"],
                    "Count Registry": [total_logs - anomaly_events, anomaly_events]
                })
                fig = px.bar(chart_data, x="Classification Metric", y="Count Registry", color="Classification Metric",
                             color_discrete_map={"Safe Traffic Stream": "#00CC96", "Mitigated Attack Vectors": "#EF553B"})
                st.plotly_chart(fig, use_container_width=True)
                
            with state_col:
                st.markdown("#### 🔒 Network Firewall State")
                if blocked_ips > 0:
                    st.error(f"CRITICAL STATE: {blocked_ips} Malicious Node locked out in Redis.")
                else:
                    st.success("NOMINAL STATE: System Secure.")

        except Exception as e:
            st.warning("Connecting to telemetry streams...")
        
        time.sleep(2)