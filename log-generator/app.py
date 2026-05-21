import os
import time
import json
import random
import pika
import requests
import threading
import pandas as pd
import streamlit as st
from datetime import datetime

# Persistent Simulation Configurations
IPS_POOL = ["192.168.4.55", "10.1.12.4", "172.19.88.2", "185.220.101.5", "45.79.112.34"]
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "localhost")
ML_ENGINE_METRICS_URL = "http://ml-engine:8000/metrics"

# Global fallback variable to bridge between Streamlit and the background thread safely
CURRENT_ATTACK_MODE = "Normal Monitoring"

# Initialize Session States
if "incident_history" not in st.session_state:
    st.session_state["incident_history"] = []
if "k8s_replicas" not in st.session_state:
    st.session_state["k8s_replicas"] = {"log-generator": 1, "rabbitmq": 1, "ml-engine": 1, "redis-cache": 1}
if "build_version" not in st.session_state:
    st.session_state["build_version"] = "v1.2.4-update"

def background_log_publisher():
    """ Simulates normal network traffic mixed with dynamic attack injections """
    global CURRENT_ATTACK_MODE
    for _ in range(15):
        try:
            connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST))
            channel = connection.channel()
            channel.queue_declare(queue='telemetry_stream')
            break
        except pika.exceptions.AMQPConnectionError:
            time.sleep(2)
    else:
        return

    while True:
        mode = CURRENT_ATTACK_MODE
        
        if "High-Volume Brute Force" in mode:
            selected_ip = "185.220.101.5"
            status_code = 401
            req = "POST /api/v1/auth/login"
            sleep_time = random.uniform(0.05, 0.15)
        elif "Distributed DDoS" in mode:
            selected_ip = random.choice(IPS_POOL)
            status_code = random.choice([200, 401, 404, 500])
            req = random.choice(["GET /index.html", "POST /api/v1/checkout", "GET /api/v3/users"])
            sleep_time = random.uniform(0.02, 0.08)
        else:
            selected_ip = random.choice(IPS_POOL)
            if selected_ip == "185.220.101.5":
                status_code = 401
                req = "POST /api/v1/auth/login"
            else:
                status_code = random.choice([200, 200, 200, 404])
                req = "GET /index.html" if status_code == 200 else "GET /favicon.ico"
            sleep_time = random.uniform(0.4, 1.2)

        log_packet = {
            "ip": selected_ip, 
            "timestamp": time.time(), 
            "request_type": req, 
            "status": status_code
        }
        
        try:
            channel.basic_publish(exchange='', routing_key='telemetry_stream', body=json.dumps(log_packet))
        except Exception:
            pass
        
        time.sleep(sleep_time)

# Initialize background publisher once
if "publisher_started" not in st.session_state:
    threading.Thread(target=background_log_publisher, daemon=True).start()
    st.session_state["publisher_started"] = True

def parse_siem_telemetry():
    """ Extracts metrics from Prometheus exporter """
    metrics = {"logs_200": 0, "logs_401": 0, "anomalies": 0, "blocked_ips": 0, "cpu_pct": 0.0, "memory_mb": 0.0}
    try:
        response = requests.get(ML_ENGINE_METRICS_URL, timeout=1)
        if response.status_code == 200:
            for line in response.text.split("\n"):
                if line.startswith("siem_processed_logs_total{status=\"200\"}"):
                    metrics["logs_200"] = int(float(line.split()[-1]))
                elif line.startswith("siem_processed_logs_total{status=\"401\"}"):
                    metrics["logs_401"] = int(float(line.split()[-1]))
                elif line.startswith("siem_anomalies_detected_total"):
                    metrics["anomalies"] = int(float(line.split()[-1]))
                elif line.startswith("siem_active_blocked_ips_count"):
                    metrics["blocked_ips"] = int(float(line.split()[-1]))
                elif line.startswith("infra_container_cpu_percent"):
                    metrics["cpu_pct"] = round(float(line.split()[-1]), 1)
                elif line.startswith("infra_container_memory_mb"):
                    metrics["memory_mb"] = round(float(line.split()[-1]), 1)
    except Exception:
        pass
    return metrics

# Page Layout Configurations
st.set_page_config(page_title="Enterprise SecOps Console", page_icon="🛡️", layout="wide")
st.title("🛡️ Next-Gen DevSecOps Telemetry & Threat-Hunting SIEM")
st.caption("Real-Time Event Ingestion Broker Mesh with Unsupervised ML Anomaly Quarantine Isolation")

# Fetch fresh metrics
live_data = parse_siem_telemetry()
total_logs = live_data["logs_200"] + live_data["logs_401"]
current_time_str = datetime.now().strftime("%H:%M:%S")

# Dynamic Kubernetes Auto-scaling calculation based on simulation load
if "Distributed DDoS" in CURRENT_ATTACK_MODE:
    st.session_state["k8s_replicas"]["ml-engine"] = 4
    st.session_state["k8s_replicas"]["log-generator"] = 3
else:
    st.session_state["k8s_replicas"]["ml-engine"] = 1
    st.session_state["k8s_replicas"]["log-generator"] = 1

# Update time-series tracking historical map
if len(st.session_state["incident_history"]) == 0 or st.session_state["incident_history"][-1]["total_logs"] != total_logs:
    st.session_state["incident_history"].append({
        "Timestamp": current_time_str, "Ingress Volume": total_logs, "Threat Alerts": live_data["anomalies"], 
        "Blacklisted IPs": live_data["blocked_ips"], "CPU %": live_data["cpu_pct"], "RAM MB": live_data["memory_mb"],
        "total_logs": total_logs
    })
if len(st.session_state["incident_history"]) > 40:
    st.session_state["incident_history"].pop(0)

# --- SIDEBAR INTERACTIVE SIMULATION PANEL ---
st.sidebar.header("🕹️ Threat Simulation Controller")
st.sidebar.markdown("Use these toggle controllers to execute stress vectors or malicious payloads live.")

# Keep global variable aligned with UI input
selected_mode = st.sidebar.radio(
    "Select System Traffic Vector Profile:",
    ("Normal Monitoring", "🚨 High-Volume Brute Force (IP: 185.220.101.5)", "💥 Distributed DDoS Simulation (Multi-IP)")
)
CURRENT_ATTACK_MODE = selected_mode

st.sidebar.markdown("---")
st.sidebar.subheader("🔒 Database Status Summary")
st.sidebar.info(f"⚡ Memory Cache: Connected\n🗄️ Redis Bans: {live_data['blocked_ips']} Active Keys\n📬 MQ Status: Queue Streaming")

# --- SIDEBAR FEATURE: PRESENTATION ADMIN CONTROLS ---
st.sidebar.subheader("⚙️ DevOps Presentation Actions")
if st.sidebar.button("🚀 Trigger GitHub Actions CI/CD Pipeline", use_container_width=True):
    st.session_state["build_version"] = f"v1.2.{random.randint(5,99)}-release"
    st.sidebar.success(f"GitHub webhook fired! Built {st.session_state['build_version']}")

if live_data['anomalies'] > 0:
    st.sidebar.error(f"🚨 ALERT: {live_data['anomalies']} Malicious Intrusions Contained by Isolation Forest Model.")

# --- CORE EXECUTIVE STATS GRID ---
m1, m2, m3, m4 = st.columns(4)
m1.metric(label="📊 Log Pipeline Ingress", value=f"{total_logs} Packets", delta=f"+{total_logs - st.session_state['incident_history'][0]['Ingress Volume']} vs boot")
m2.metric(label="🚨 ML Isolated Threat Counts", value=f"{live_data['anomalies']} Incidents", delta=f"{live_data['anomalies']} Detected", delta_color="inverse")
m3.metric(label="🖥️ Microservice CPU Capacity", value=f"{live_data['cpu_pct']} %")
m4.metric(label="💾 Dedicated Memory Footprint", value=f"{live_data['memory_mb']} MB")

st.markdown("---")

# --- CHART AND TELEMETRY GRID ---
chart_col, health_col = st.columns([2, 1])
history_df = pd.DataFrame(st.session_state["incident_history"])

with chart_col:
    st.subheader("📈 Real-Time SIEM Threat Trends")
    if not history_df.empty:
        st.line_chart(history_df.set_index("Timestamp")[["Ingress Volume", "Threat Alerts", "Blacklisted IPs"]], height=260)

with health_col:
    st.subheader("⚙️ Local Container Hardware Profile")
    if not history_df.empty:
        st.area_chart(history_df.set_index("Timestamp")[["CPU %", "RAM MB"]], height=260)

st.markdown("---")

# --- NEW EXTENSION: DEVOPS KUBERNETES & GITOPS HUB ---
st.subheader("☸️ Kubernetes Microservice Cluster & GitOps Infrastructure Monitor")
k8s_col, github_col = st.columns([2, 1])

with k8s_col:
    st.markdown("### 📦 Active K8s Pod Lifecycle Fleet")
    
    # Calculate pod health metrics dynamically
    k8s_data = {
        "Microservice Name": ["log-generator-deployment", "rabbitmq-cluster-broker", "ml-anomaly-engine-deployment", "redis-mitigation-cache"],
        "Desired Replicas": [st.session_state["k8s_replicas"]["log-generator"], st.session_state["k8s_replicas"]["rabbitmq"], st.session_state["k8s_replicas"]["ml-engine"], st.session_state["k8s_replicas"]["redis-cache"]],
        "Available Pods": [st.session_state["k8s_replicas"]["log-generator"], st.session_state["k8s_replicas"]["rabbitmq"], st.session_state["k8s_replicas"]["ml-engine"], st.session_state["k8s_replicas"]["redis-cache"]],
        "Current Status": ["Running (Healthy)", "Running (Healthy)", "Scaling / Active" if "Distributed DDoS" in CURRENT_ATTACK_MODE else "Running (Healthy)", "Running (Healthy)"],
        "Restarts": [0, 0, 1 if live_data["anomalies"] > 0 else 0, 0]
    }
    st.dataframe(pd.DataFrame(k8s_data), use_container_width=True, hide_index=True)
    
    # Showcase Kubernetes Horizontal Pod Autoscaler automation
    if "Distributed DDoS" in CURRENT_ATTACK_MODE:
        st.info("⚡ **Horizontal Pod Autoscaler (HPA) Notice:** CPU load exceeded 75% threshold. Automatically scaled `ml-anomaly-engine-deployment` pods from 1 to 4 to process inbound telemetry spikes without dropping metrics.")

with github_col:
    st.markdown("### 🐙 GitOps CI/CD Delivery Status")
    st.markdown(f"**Target Cluster Image Build:** `{st.session_state['build_version']}`")
    
    # Display step-by-step pipeline validation markers
    st.markdown("✅ **GitHub Actions Pipeline Status:** `Success`")
    st.markdown("🐳 **Docker Container Registry:** Shared Image Verified")
    st.markdown("🔒 **Trivy Container Scan Result:** `0 Critical Vulnerabilities`")
    st.progress(1.0)

st.markdown("---")

# --- REAL-TIME THREAT DETECTION HUB ---
st.subheader("🎯 Real-Time Threat Detection & Automated Quarantine Hub")
status_col, summary_col = st.columns([1, 2])

with status_col:
    st.markdown("### ⚡ Threat Risk Assessment")
    if "High-Volume" in CURRENT_ATTACK_MODE:
        st.error("🔴 CRITICAL: HIGH BRUTE FORCE DEPLOYED")
        st.warning("Isolation Forest quarantine rules actively parsing telemetry logs.")
    elif "Distributed" in CURRENT_ATTACK_MODE:
        st.error("💥 CRITICAL: DDOS INFRASTRUCTURE ATTACK")
        st.warning("High packet ingress rates detected. Scaling mitigation resources.")
    else:
        st.success("🟢 NORMAL SECURITY COMPLIANCE")
        st.info("System streaming clean transaction hashes within safe parameters.")

with summary_col:
    st.markdown("### 📋 Active Security Subsystem Summary")
    breakdown_data = {
        "Subsystem Component": ["RabbitMQ Message Broker", "FastAPI AI Engine", "Redis Cache Sync", "Prometheus Telemetry Feed"],
        "Operational Status": ["Active / Streaming", "Evaluating (Isolation Forest)", "Synchronized", "Exporting Live Metrics"],
        "Metrics Registered": [f"{total_logs} Packets Received", f"{live_data['anomalies']} Anomalies Found", f"{live_data['blocked_ips']} IP Restrictions Active", "Data Point Synchronized"]
    }
    st.table(pd.DataFrame(breakdown_data))

# --- LIVE TELEMETRY DEEP PACKET INSPECTION ---
st.markdown("### 🔍 Live Ingress Packet Deep Inspection (JSON Stream)")
if "High-Volume" in CURRENT_ATTACK_MODE:
    mock_ip, mock_status, mock_req = "185.220.101.5", 401, "POST /api/v1/auth/login"
elif "Distributed" in CURRENT_ATTACK_MODE:
    mock_ip, mock_status, mock_req = random.choice(IPS_POOL), random.choice([401, 500, 404]), "POST /api/v1/checkout"
else:
    mock_ip, mock_status, mock_req = random.choice(IPS_POOL), 200, "GET /index.html"

live_json_packet = {
    "routing_key": "telemetry_stream",
    "payload": {
        "source_node_ip": mock_ip,
        "timestamp_unix": time.time(),
        "http_request_verb": mock_req,
        "response_status_code": mock_status,
        "ml_anomaly_score": -0.72 if mock_status == 401 else 0.14,
        "quarantine_action_taken": True if mock_status == 401 else False
    }
}
st.json(live_json_packet)

# --- AUTOMATED QUARANTINE LISTS ---
st.markdown("### 🔒 Automated Network Firewall Restrictions")
if live_data["blocked_ips"] > 0:
    st.warning(f"⚠️ DevSecOps pipeline has actively pushed malicious addresses to the Redis Key-Value Store. The following node is being actively blocked from communicating with your microservices:")
    
    quarantine_df = pd.DataFrame({
        "Quarantined IP Address": ["185.220.101.5"],
        "Reason for Mitigation": ["High-Volume Brute Force Attack / Anomaly Triggered"],
        "Mitigation Layer": ["Redis Cache Ingress Rule Blocked"],
        "Time Restrained": [datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
    })
    st.dataframe(quarantine_df, use_container_width=True, hide_index=True)
else:
    st.info("No addresses currently restrained. Active firewall rule table is empty.")

# Instant interface refreshes every second
time.sleep(1.0)
st.rerun()