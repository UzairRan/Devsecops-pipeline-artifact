import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import requests
import random
import os

# ----------------------------
# 🎨 PAGE CONFIG — MUST BE FIRST STREAMLIT COMMAND
# ----------------------------
st.set_page_config(
    page_title="DevSecOps Pulse",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ----------------------------
# 📁 SIDEBAR REPORT DOWNLOADS
# ----------------------------
st.sidebar.subheader("Reports")
report_files = [f for f in os.listdir("../reports") if f.endswith(".json")] if os.path.exists("../reports") else []
for rf in report_files:
    with open(os.path.join("../reports", rf), "r") as fh:
        st.sidebar.download_button(label=f"Download {rf}", data=fh.read(), file_name=rf)

# Backend API Configuration
BACKEND_URL = "http://localhost:8000"  # Change to your backend URL

# ----------------------------
# 🎨 THEME MANAGEMENT
# ----------------------------
def apply_theme(theme):
    if theme == "dark":
        return """
        <style>
            .main { 
                background-color: #0e1117; 
                color: #fafafa;
                padding: 1.5rem; 
            }
            .stTabs [data-basewidth="100%"] { 
                background: #262730; 
                border-radius: 12px; 
                box-shadow: 0 2px 12px rgba(255,255,255,0.08); 
            }
            .stMetric { 
                background: #1e1e1e; 
                padding: 18px; 
                border-radius: 12px; 
                box-shadow: 0 2px 6px rgba(255,255,255,0.04); 
                border: 1px solid #444; 
            }
            h1, h2, h3 { color: #60a5fa; font-weight: 700; }
            .critical { color: #f87171; font-weight: 600; }
            .high { color: #fb923c; font-weight: 600; }
            .medium { color: #fbbf24; }
            .low { color: #9ca3af; }
            .alert-box {
                background: #7f1d1d;
                border-left: 4px solid #ef4444;
                padding: 12px;
                border-radius: 8px;
                margin: 10px 0;
                color: white;
            }
            .insight-box {
                background: #064e3b;
                border-left: 4px solid #10b981;
                padding: 12px;
                border-radius: 8px;
                margin: 10px 0;
                color: white;
            }
            .log-line {
                font-family: 'Courier New', monospace;
                font-size: 0.9em;
                line-height: 1.5;
                color: #60a5fa;
            }
            .vulnerability-card {
                background: #1e1e1e;
                padding: 20px;
                border-radius: 12px;
                margin: 16px 0;
                border-left: 6px solid;
                box-shadow: 0 4px 12px rgba(255,255,255,0.1);
                transition: transform 0.2s ease;
            }
            .vulnerability-card:hover {
                transform: translateY(-2px);
            }
            .critical-card { border-left-color: #ef4444; background: linear-gradient(135deg, #7f1d1d 0%, #991b1b 100%); }
            .high-card { border-left-color: #f97316; background: linear-gradient(135deg, #7c2d12 0%, #9a3412 100%); }
            .medium-card { border-left-color: #f59e0b; background: linear-gradient(135deg, #78350f 0%, #92400e 100%); }
            .low-card { border-left-color: #64748b; background: linear-gradient(135deg, #374151 0%, #4b5563 100%); }
            .priority-badge {
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 0.8em;
                font-weight: 600;
                margin-left: 10px;
            }
            .immediate-priority { background: #ef4444; color: white; }
            .high-priority { background: #f97316; color: white; }
            .medium-priority { background: #f59e0b; color: black; }
        </style>
        """
    else:
        return """
        <style>
            .main { padding: 1.5rem; }
            .stTabs [data-basewidth="100%"] { 
                background: white; 
                border-radius: 12px; 
                box-shadow: 0 2px 12px rgba(0,0,0,0.08); 
            }
            .stMetric { 
                background: #f8fafc; 
                padding: 18px; 
                border-radius: 12px; 
                box-shadow: 0 2px 6px rgba(0,0,0,0.04); 
                border: 1px solid #e2e8f0; 
            }
            h1, h2, h3 { color: #1e3a8a; font-weight: 700; }
            .critical { color: #ef4444; font-weight: 600; }
            .high { color: #f97316; font-weight: 600; }
            .medium { color: #f59e0b; }
            .low { color: #64748b; }
            .alert-box {
                background: #fef2f2;
                border-left: 4px solid #ef4444;
                padding: 12px;
                border-radius: 8px;
                margin: 10px 0;
            }
            .insight-box {
                background: #f0fdf4;
                border-left: 4px solid #10b981;
                padding: 12px;
                border-radius: 8px;
                margin: 10px 0;
            }
            .log-line {
                font-family: 'Courier New', monospace;
                font-size: 0.9em;
                line-height: 1.5;
                color: #1e3a8a;
            }
            .vulnerability-card {
                background: #f8fafc;
                padding: 20px;
                border-radius: 12px;
                margin: 16px 0;
                border-left: 6px solid;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                transition: transform 0.2s ease;
            }
            .vulnerability-card:hover {
                transform: translateY(-2px);
            }
            .critical-card { border-left-color: #ef4444; background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%); }
            .high-card { border-left-color: #f97316; background: linear-gradient(135deg, #fff7ed 0%, #ffedd5 100%); }
            .medium-card { border-left-color: #f59e0b; background: linear-gradient(135deg, #fffbeb 0%, #fef3c7 100%); }
            .low-card { border-left-color: #64748b; background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%); }
            .priority-badge {
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 0.8em;
                font-weight: 600;
                margin-left: 10px;
            }
            .immediate-priority { background: #ef4444; color: white; }
            .high-priority { background: #f97316; color: white; }
            .medium-priority { background: #f59e0b; color: black; }
        </style>
        """

# Theme selector
st.sidebar.title("Filters")
theme = st.sidebar.radio("Theme Mode", ["Light", "Dark"], index=0)
st.markdown(apply_theme(theme.lower()), unsafe_allow_html=True)

# ----------------------------
# 🖥️ SIDEBAR FILTER CONTROLS
# ----------------------------
time_range = st.sidebar.slider("Time Range (Days)", 7, 90, 30)
env_filter = st.sidebar.selectbox("Environment", ["All", "Development", "Staging", "Production"])
severity_filter = st.sidebar.multiselect(
    "Severity Levels", ["Critical", "High", "Medium", "Low"], default=["Critical", "High"]
)
refresh = st.sidebar.button("🔄 Refresh Data")

# ----------------------------
# BACKEND FETCH FUNCTIONS
# ----------------------------
def fetch_real_metrics(days=30, env_filter="All"):
    try:
        response = requests.get(f"{BACKEND_URL}/api/metrics?days={days}")
        if response.status_code == 200:
            data = response.json()
            metrics = data.get("metrics", [])
            if metrics:
                df = pd.DataFrame(metrics)
                df["Date"] = pd.to_datetime(df["Date"])
                if env_filter != "All":
                    df = df[df["Environment"] == env_filter]
                return df, data.get("summary", {})
    except Exception as e:
        st.error(f"Error fetching metrics: {e}")
    return generate_fallback_data(days, env_filter), {}

def fetch_real_vulnerabilities():
    try:
        response = requests.get(f"{BACKEND_URL}/api/vulnerabilities")
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return generate_fallback_vulns()

def fetch_real_workflow_runs():
    try:
        response = requests.get(f"{BACKEND_URL}/api/workflow-runs")
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return {"runs": []}

# ----------------------------
# FALLBACK DATA
# ----------------------------
def generate_fallback_data(days, env_filter):
    dates = [datetime.today() - timedelta(days=i) for i in range(days)][::-1]
    data = [{
        "Date": date,
        "Success Rate (%)": 85 + random.randint(-10, 10),
        "Build Time (s)": 60 + random.randint(-20, 20),
        "Vulnerabilities": random.randint(0, 15),
        "Environment": random.choice(["Development", "Staging", "Production"])
    } for date in dates]
    return pd.DataFrame(data)

def generate_fallback_vulns():
    packages = ["requests", "urllib3", "flask", "jinja2"]
    titles = ["Improper Input Validation", "Open Redirect", "Insecure Session Handling"]
    return [{
        "id": f"CVE-2023-{random.randint(1000,9999)}",
        "package": random.choice(packages),
        "severity": random.choice(["Critical", "High", "Medium", "Low"]),
        "title": random.choice(titles),
        "environment": random.choice(["Development", "Staging", "Production"])
    } for _ in range(random.randint(1, 8))]

# ----------------------------
# FETCH DATA
# ----------------------------
df, summary = fetch_real_metrics(time_range, env_filter)
vulns = fetch_real_vulnerabilities()
workflow_runs = fetch_real_workflow_runs()

# ----------------------------
# SUMMARY
# ----------------------------
if summary:
    avg_success = summary.get("success_rate", 85)
    avg_time = summary.get("avg_build_time", 60)
    total_builds = summary.get("total_runs", len(df))
else:
    avg_success = df["Success Rate (%)"].mean()
    avg_time = df["Build Time (s)"].mean()
    total_builds = len(df)

total_vulns = (
    sum(df["Vulnerabilities"]) if "Vulnerabilities" in df.columns else 0
)

# count by severity
severity_counts = {}
for v in vulns:
    severity_counts[v["severity"]] = severity_counts.get(v["severity"], 0) + 1

critical_vulns = severity_counts.get("Critical", 0)
high_vulns = severity_counts.get("High", 0)
medium_vulns = severity_counts.get("Medium", 0)
low_vulns = severity_counts.get("Low", 0)

# severity filter
if severity_filter:
    vulns = [v for v in vulns if v["severity"] in severity_filter]

# environment filter
if env_filter != "All":
    vulns = [v for v in vulns if v.get("environment") == env_filter]

# ----------------------------
# TOP 3
# ----------------------------
def get_top_vulnerabilities_with_remediation(vulns_list):
    severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    sorted_vulns = sorted(vulns_list, key=lambda x: severity_order[x["severity"]], reverse=True)
    top_3 = sorted_vulns[:3]

    for vuln in top_3:
        if "SQL" in vuln["title"]:
            vuln["remediation"] = "Use parameterized queries."
            vuln["priority"] = "IMMEDIATE"
        elif "XSS" in vuln["title"]:
            vuln["remediation"] = "Enable output encoding and CSP."
            vuln["priority"] = "IMMEDIATE"
        else:
            vuln["remediation"] = "Update to latest secure version."
            vuln["priority"] = "HIGH"

    return top_3

top_vulnerabilities = get_top_vulnerabilities_with_remediation(vulns)

# ----------------------------
# TABS
# ----------------------------
st.title("🛡️ DevSecOps Pulse")
st.markdown("Operational insights for your secure CI/CD pipeline")

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "Overview Dashboard",
    "Pipeline Analytics",
    "Security Center",
    "Build History & Logs",
    "🚨 Critical Vulnerabilities"
])

# ----------------------------
# TAB 1: OVERVIEW
# ----------------------------
with tab1:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Build Success", f"{avg_success:.1f}%")
    c2.metric("Avg Build Time", f"{avg_time:.0f}s")
    c3.metric("Total Vulns", int(total_vulns))
    c4.metric("Total Runs", total_builds)

    # Health
    if avg_success >= 90:
        st.markdown("### 🟢 Pipeline Health: Excellent")
    elif avg_success >= 80:
        st.markdown("### 🟡 Pipeline Health: Good")
    else:
        st.markdown("### 🔴 Pipeline Health: Needs Attention")

# ----------------------------
# TAB 2: ANALYTICS
# ----------------------------
with tab2:
    st.subheader("Success Rate Trend")
    if not df.empty:
        fig = px.line(df, x="Date", y="Success Rate (%)", color="Environment")
        st.plotly_chart(fig, use_container_width=True)

# ----------------------------
# TAB 3: SECURITY CENTER
# ----------------------------
with tab3:
    st.subheader("Severity Distribution")
    if severity_counts:
        vuln_df = pd.DataFrame({
            "Severity": list(severity_counts.keys()),
            "Count": list(severity_counts.values())
        })
        fig = px.pie(vuln_df, values="Count", names="Severity")
        st.plotly_chart(fig)

# ----------------------------
# TAB 4: LOGS
# ----------------------------
# ----------------------------
# TAB 4: BUILD HISTORY & LOGS
# ----------------------------
with tab4:
    st.subheader("Latest Build Output")

    if workflow_runs and workflow_runs.get("runs"):
        latest_run = workflow_runs["runs"][0]
        build_id = latest_run.get("id", "N/A")
        last_env = latest_run.get("head_branch", "main")
        last_time = latest_run.get("created_at", datetime.now().isoformat())
        status = latest_run.get("conclusion", "unknown")
        duration = latest_run.get("duration", 60)

        status_emoji = "🟢" if status == "success" else "🔴" if status == "failure" else "🟡"
        final_status = "SUCCESS" if status == "success" else "FAILED" if status == "failure" else "RUNNING"
        current_vuln_count = len(vulns)

        # Real logs
        log_lines = [
            f"[{last_time}] {status_emoji} Build #{build_id} started for branch '{last_env}'",
            f"[{last_time.replace('T', ' ').split('.')[0]}] 📦 Triggered by GitHub Actions",
            f"[{last_time.replace('T', ' ').split('.')[0]}] 🔄 Running security scans",
            f"[{last_time.replace('T', ' ').split('.')[0]}] 🔍 Security scans completed",
            f"[{last_time.replace('T', ' ').split('.')[0]}] ⚠️ {current_vuln_count} vulnerabilities detected",
            f"[{last_time.replace('T', ' ').split('.')[0]}] 📊 Build {final_status} after {duration}s"
        ]

        log_html = "<br>".join(log_lines)

        st.markdown(f"""
        <div style="background: #f8fafc; padding: 16px; border-radius: 10px;
                    border: 1px solid #e2e8f0; font-family: 'Courier New', monospace;
                    font-size: 0.9em; line-height: 1.5;">
            {log_html}
        </div>
        """, unsafe_allow_html=True)

        # Build summary
        st.markdown(f"""
        **Build Summary**
        - **Build ID:** #{build_id}
        - **Branch:** {last_env}
        - **Status:** {final_status}
        - **Duration:** {duration}s
        - **Vulnerabilities:** {current_vuln_count}
        - **GitHub Link:** [Open Workflow]({latest_run.get('html_url', '#')})
        """)

    else:
        st.warning("⚠️ Could not fetch real workflow data — showing sample data.")
        
        # Fallback logs
        last_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        current_vuln_count = len(vulns)

        log_lines = [
            f"[{last_time}] 🟢 Build #142 started for 'main'",
            f"[{last_time.replace('T', ' ').split('.')[0]}] 📦 Installing dependencies...",
            f"[{last_time.replace('T', ' ').split('.')[0]}] ✅ Tests passed (32/32)",
            f"[{last_time.replace('T', ' ').split('.')[0]}] 🔍 Running Trivy scan...",
            f"[{last_time.replace('T', ' ').split('.')[0]}] ⚠️ {current_vuln_count} vulnerabilities detected",
            f"[{last_time.replace('T', ' ').split('.')[0]}] 🚀 Deploying via Ansible playbook",
            f"[{last_time.replace('T', ' ').split('.')[0]}] 🟢 Build #142 SUCCESS (76s)"
        ]

        log_html = "<br>".join(log_lines)
        st.markdown(f"""
        <div style="background: #f8fafc; padding: 16px; border-radius: 10px;
                    border: 1px solid #e2e8f0; font-family: 'Courier New', monospace;
                    font-size: 0.9em; line-height: 1.5;">
            {log_html}
        </div>
        """, unsafe_allow_html=True)


# ----------------------------
# TAB 5: CRITICAL
# ----------------------------
with tab5:
    st.header("🚨 Critical Vulnerabilities")
    if top_vulnerabilities:
        for vuln in top_vulnerabilities:
            st.write(vuln)
    else:
        st.success("No critical vulnerabilities detected.")

# ----------------------------
# EXPORT
# ----------------------------
st.sidebar.markdown("---")
st.sidebar.subheader("Export")
if st.sidebar.button("Download Metrics (CSV)"):
    csv = df.to_csv(index=False)
    st.sidebar.download_button("Download Now", csv, "pipeline_metrics.csv")

if refresh:
    st.rerun()
