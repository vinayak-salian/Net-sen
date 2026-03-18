import streamlit as st
import pandas as pd
import boto3
from datetime import datetime
import pytz
import streamlit.components.v1 as components

# --- PAGE CONFIG & CSS ---
st.set_page_config(page_title="NetSentinel C&C", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;700&display=swap');
    html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
    .stApp { background-color: #050505; background-image: radial-gradient(circle at 50% 0%, #171124 0%, #050505 50%); color: #e2e8f0; }
    h1, h2, h3 { color: #f8fafc; font-weight: 600 !important; letter-spacing: -0.025em; }
    .main-header { font-size: 2.5rem; background: linear-gradient(90deg, #3b82f6, #8b5cf6, #ec4899); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 0rem; padding-bottom: 0rem; font-weight: 800; letter-spacing: -1px; }
    .status-badge { display: inline-block; padding: 0.35rem 1rem; border-radius: 50px; background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.4); color: #10b981; font-size: 0.85rem; font-weight: 600; margin-top: 1rem; box-shadow: 0 0 15px rgba(16, 185, 129, 0.2); letter-spacing: 1px; }
    .cyber-card { background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 8px; padding: 1.5rem; position: relative; box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.5); backdrop-filter: blur(12px); transition: transform 0.2s ease, box-shadow 0.2s ease; }
    .cyber-card:hover { transform: translateY(-2px); box-shadow: 0 8px 25px -5px rgba(0, 0, 0, 0.7); }
    .cyber-card::before, .cyber-card::after { content: ''; position: absolute; width: 15px; height: 15px; border: 2px solid transparent; pointer-events: none; }
    .cyber-card::before { top: -1px; left: -1px; border-top-color: var(--card-color); border-left-color: var(--card-color); border-top-left-radius: 8px; }
    .cyber-card::after { bottom: -1px; right: -1px; border-bottom-color: var(--card-color); border-right-color: var(--card-color); border-bottom-right-radius: 8px; }
    .card-blue { --card-color: #3b82f6; } .card-orange { --card-color: #ef4444; } .card-purple { --card-color: #8b5cf6; }
    .cyber-card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
    .cyber-card-title { font-size: 0.8rem; color: #94a3b8; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; }
    .cyber-card-icon { font-size: 1.5rem; opacity: 0.9; }
    .cyber-card-value { font-size: 2.5rem; font-weight: 700; color: #f8fafc; line-height: 1; font-family: 'Fira Code', monospace; }
    .dataframe-container { border-radius: 8px; overflow: hidden; border: 1px solid rgba(139, 92, 246, 0.2); background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(10px); box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3); }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; font-family: 'Fira Code', monospace; color: #cbd5e1; }
    th { text-align: left; padding: 14px 16px; background-color: rgba(30, 41, 59, 0.9); color: #8b5cf6; font-weight: 600; text-transform: uppercase; font-size: 0.75rem; border-bottom: 2px solid rgba(139, 92, 246, 0.3); letter-spacing: 1px;}
    td { padding: 12px 16px; border-bottom: 1px solid rgba(255, 255, 255, 0.03); }
    tr:hover td { background-color: rgba(139, 92, 246, 0.08); }
    div.stButton > button { background-color: rgba(30, 41, 59, 0.8); color: #f8fafc; border: 1px solid rgba(255,255,255,0.1); border-radius: 6px; transition: all 0.2s; }
    div.stButton > button:hover { border-color: #8b5cf6; color: #8b5cf6; background-color: rgba(139, 92, 246, 0.1); }
    code { color: #3b82f6 !important; background: rgba(59, 130, 246, 0.1) !important; }
    .stTextInput input { background-color: rgba(15, 23, 42, 0.6) !important; color: #3b82f6 !important; border: 1px solid rgba(59, 130, 246, 0.3) !important; font-family: 'Fira Code', monospace; }
</style>
""", unsafe_allow_html=True)

# --- 1. AWS CONFIG & FUNCTIONS ---
COGNITO_CLIENT_ID = "f5etbjhkikcoe31g58iqkmv1j"
REGION = "us-east-1"
ist = pytz.timezone('Asia/Kolkata')

def check_aws_auth(username, password):
    if not username or not password: return False, "Please enter both username and password."
    try:
        client = boto3.client('cognito-idp', region_name=REGION, aws_access_key_id=st.secrets["AWS_ACCESS_KEY_ID"], aws_secret_access_key=st.secrets["AWS_SECRET_ACCESS_KEY"])
        client.initiate_auth(ClientId=COGNITO_CLIENT_ID, AuthFlow='USER_PASSWORD_AUTH', AuthParameters={'USERNAME': username, 'PASSWORD': password})
        return True, username
    except Exception as e: return False, "Authentication service error. Please try again."

def fetch_live_devices():
    try:
        table = boto3.resource('dynamodb', region_name=REGION, aws_access_key_id=st.secrets["AWS_ACCESS_KEY_ID"], aws_secret_access_key=st.secrets["AWS_SECRET_ACCESS_KEY"]).Table('NetSentinel_Data')
        response = table.scan()
        formatted_devices = []
        for item in response.get('Items', []):
            if 'query' in item: continue
            raw_time = item.get('last_seen')
            last_seen_str = datetime.fromtimestamp(int(raw_time), ist).strftime('%H:%M:%S | %d %b') if raw_time else "Initial Scan"
            formatted_devices.append({"mac": item.get('mac_address', 'Unknown'), "ip": item.get('ip_address', 'Unknown'), "name": item.get('device_name', 'Unknown-Device'), "status": item.get('status', 'PENDING'), "last_seen": last_seen_str})
        return formatted_devices
    except: return []

def update_device_status(mac, ip, new_status, new_name=None):
    try:
        table = boto3.resource('dynamodb', region_name=REGION, aws_access_key_id=st.secrets["AWS_ACCESS_KEY_ID"], aws_secret_access_key=st.secrets["AWS_SECRET_ACCESS_KEY"]).Table('NetSentinel_Data')
        u_expr = "SET #st = :val"
        e_vals = {':val': new_status}
        if new_name: u_expr += ", device_name = :n"; e_vals[':n'] = new_name
        table.update_item(Key={'mac_address': mac}, UpdateExpression=u_expr, ExpressionAttributeNames={'#st': 'status'}, ExpressionAttributeValues=e_vals)
        return True
    except: return False

def toggle_dns_monitoring(mac, state_boolean):
    try:
        table = boto3.resource('dynamodb', region_name=REGION, aws_access_key_id=st.secrets["AWS_ACCESS_KEY_ID"], aws_secret_access_key=st.secrets["AWS_SECRET_ACCESS_KEY"]).Table('NetSentinel_Data')
        table.update_item(Key={'mac_address': mac}, UpdateExpression="SET dns_monitor = :val", ExpressionAttributeValues={':val': state_boolean})
    except Exception as e: st.error(f"Failed to issue C2 command: {e}")

def fetch_live_dns():
    """🚨 FIX: Time-based Filtering. Only pulls logs from the last 5 minutes."""
    try:
        table = boto3.resource('dynamodb', region_name=REGION, aws_access_key_id=st.secrets["AWS_ACCESS_KEY_ID"], aws_secret_access_key=st.secrets["AWS_SECRET_ACCESS_KEY"]).Table('NetSentinel_Data')
        response = table.scan()
        
        current_time = int(time.time())
        five_minutes_ago = current_time - 300 # 300 seconds
        
        logs = []
        for item in response.get('Items', []):
            if 'query' in item:
                log_time = item.get('timestamp')
                # Only include the log if it exists and happened in the last 5 mins
                if log_time and int(log_time) > five_minutes_ago:
                    logs.append({
                        "Timestamp": log_time,
                        "Source IP": item.get('source_ip', 'Unknown'),
                        "Query": item.get('query', 'Unknown')
                    })
                    
        # Sort logs so the newest queries appear at the top
        logs = sorted(logs, key=lambda x: int(x['Timestamp']), reverse=True)
        return logs
    except Exception: return []

def create_card(title, value, icon, color_class):
    return f'<div class="cyber-card {color_class}"><div class="cyber-card-header"><span class="cyber-card-title">{title}</span><span class="cyber-card-icon">{icon}</span></div><div class="cyber-card-body"><span class="cyber-card-value">{value}</span></div></div>'

# --- 2. SESSION STATE INITIALIZATION ---
if "authentication_status" not in st.session_state: st.session_state["authentication_status"] = None
if "name" not in st.session_state: st.session_state["name"] = None
if 'blacklist' not in st.session_state: st.session_state.blacklist = []
if 'devices' not in st.session_state: st.session_state.devices = []
if 'dns_filter_ip' not in st.session_state: st.session_state.dns_filter_ip = None
if 'dns_filter_mac' not in st.session_state: st.session_state.dns_filter_mac = None

# --- 3. RENDER LOGIN ---
if st.session_state["authentication_status"] is not True:
    st.markdown('<div class="main-header" style="text-align: center; margin-top: 10vh;">NetSentinel Login</div><br>', unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        with st.form("Login"):
            username = st.text_input("Email/Username")
            password = st.text_input("Password", type="password")
            if st.form_submit_button("Authenticate"):
                success, info = check_aws_auth(username, password)
                if success:
                    st.session_state["authentication_status"] = True; st.session_state["name"] = info; st.rerun()
                else: st.error(f"Access Denied: {info}")

# --- 4. SHOW DASHBOARD ---
if st.session_state["authentication_status"] is True:
    
    st.session_state.devices = fetch_live_devices()
    live_dns_logs = fetch_live_dns()
    
    col1, col2 = st.columns([2, 1])
    with col1: st.markdown('<div class="main-header">NetSentinel Command & Control</div><div class="status-badge">🟢 AGENT OPERATIONAL • SECURE LINK</div>', unsafe_allow_html=True)
    with col2:
        components.html(f'<div style="text-align: right; padding-top: 0.5rem; color: #94a3b8; font-family: \'Fira Code\', monospace; font-size: 14px; font-weight: 500;"><div id="live-clock">SYS_TIME // Loading...</div><div style="margin-top: 4px; color: #8b5cf6;">ADMIN // {st.session_state["name"]}</div></div><script>function updateTime() {{ var now = new Date(); document.getElementById("live-clock").innerText = "SYS_TIME // " + now.toLocaleTimeString("en-US", {{ hour12: false, timeZone: "Asia/Kolkata" }}) + " IST"; }} setInterval(updateTime, 1000); updateTime();</script>', height=60)
        if st.button("Terminate Session", use_container_width=True): st.session_state["authentication_status"] = None; st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    m1, m2, m3 = st.columns(3)
    with m1: st.markdown(create_card("LIVE DEVICES", len(st.session_state.devices), "📡", "card-blue"), unsafe_allow_html=True)
    with m2: st.markdown(create_card("CONTAINMENT ZONE", len(st.session_state.blacklist), "🚫", "card-orange"), unsafe_allow_html=True)
    with m3: st.markdown(create_card("DNS QUERIES", len(live_dns_logs), "🔗", "card-purple"), unsafe_allow_html=True)

    st.markdown("<br><hr style='border-color: rgba(255,255,255,0.05);'><br>", unsafe_allow_html=True)

    st.markdown("### 🚫 Active Mitigation (Blacklist)")
    unique_blacklist = list(set(st.session_state.blacklist))
    st.session_state.blacklist = unique_blacklist
    
    if unique_blacklist:
        for mac in unique_blacklist:
            b_col1, b_col2 = st.columns([4, 1])
            b_col1.error(f"BLOCKED MAC: `{mac}` - Routing to void.")
            if b_col2.button("🔓 Unblock", key=f"unblock_{mac}"):
                if update_device_status(mac, "Unknown", "PENDING"): 
                    st.session_state.blacklist.remove(mac); st.rerun()
    else: st.markdown("<div style=\"padding: 1.5rem; text-align: center; background: rgba(30, 41, 59, 0.4); border-radius: 8px; border: 1px dashed rgba(239, 68, 68, 0.3); color: #94a3b8; font-family: 'Fira Code', monospace;\">Containment zone is currently empty.</div>", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    st.markdown("### 📡 Live Network Status")
    if len(st.session_state.devices) > 0:
        h1, h2, h3, h_time, h4, h5 = st.columns([2, 2, 2, 2, 1, 3]) 
        h1.write("**Device Name**"); h2.write("**MAC Address**"); h3.write("**IP Address**"); h_time.write("**Last Seen**"); h4.write("**Status**"); h5.write("**Action Center**")

        for index, row in enumerate(st.session_state.devices):
            if row['status'] == 'BLOCKED': continue
            c1, c2, c3, c_time, c4, c5 = st.columns([2, 2, 2, 2, 1, 3])
            
            with c1:
                if row['status'] == "PENDING": custom_name = st.text_input("Name", value=row['name'], key=f"name_{row['mac']}", label_visibility="collapsed")
                else: st.write(f"**{row['name']}**"); custom_name = row['name'] 
            
            c2.code(row['mac']); c3.code(row['ip']); c_time.markdown(f"<span style='color: #94a3b8; font-family: \"Fira Code\", monospace;'>{row['last_seen']}</span>", unsafe_allow_html=True)
            
            with c4:
                if row['status'] == "TRUSTED": st.markdown("<span style='color: #10b981; font-weight: bold; letter-spacing: 0.05em;'>TRUSTED</span>", unsafe_allow_html=True)
                else: st.markdown("<span style='color: #f59e0b; font-weight: bold; letter-spacing: 0.05em;'>PENDING</span>", unsafe_allow_html=True)
                    
            with c5:
                if row['status'] == "PENDING":
                    bc1, bc2, bc3 = st.columns(3)
                    if bc1.button("✅ Trust", key=f"t_{row['mac']}"):
                        if update_device_status(row['mac'], row['ip'], "TRUSTED", new_name=custom_name): st.rerun() 
                    if bc2.button("🚫 Block", key=f"b_{row['mac']}"):
                        if update_device_status(row['mac'], row['ip'], "BLOCKED"):
                            if row['mac'] not in st.session_state.blacklist: st.session_state.blacklist.append(row['mac'])
                            st.rerun()
                    if st.session_state.dns_filter_mac == row['mac']:
                        if bc3.button("✖️ Stop", key=f"stop_dns_{row['mac']}"):
                            toggle_dns_monitoring(row['mac'], False); st.session_state.dns_filter_ip = None; st.session_state.dns_filter_mac = None; st.rerun()
                    else:
                        if bc3.button("🔍 DNS", key=f"dns_{row['mac']}"):
                            if st.session_state.dns_filter_mac: toggle_dns_monitoring(st.session_state.dns_filter_mac, False)
                            toggle_dns_monitoring(row['mac'], True); st.session_state.dns_filter_ip = row['ip']; st.session_state.dns_filter_mac = row['mac']; st.rerun()
                else:
                    bc1, bc2 = st.columns(2)
                    if bc1.button("🚫 Block", key=f"b_{row['mac']}"):
                        if update_device_status(row['mac'], row['ip'], "BLOCKED"):
                            if row['mac'] not in st.session_state.blacklist: st.session_state.blacklist.append(row['mac'])
                            st.rerun()
                    if st.session_state.dns_filter_mac == row['mac']:
                        if bc2.button("✖️ Stop", key=f"stop_dns_{row['mac']}"):
                            toggle_dns_monitoring(row['mac'], False); st.session_state.dns_filter_ip = None; st.session_state.dns_filter_mac = None; st.rerun()
                    else:
                        if bc2.button("🔍 DNS", key=f"dns_{row['mac']}"):
                            if st.session_state.dns_filter_mac: toggle_dns_monitoring(st.session_state.dns_filter_mac, False)
                            toggle_dns_monitoring(row['mac'], True); st.session_state.dns_filter_ip = row['ip']; st.session_state.dns_filter_mac = row['mac']; st.rerun()
    else:
        st.markdown("<div style=\"padding: 1.5rem; text-align: center; background: rgba(30, 41, 59, 0.4); border-radius: 8px; border: 1px dashed rgba(139, 92, 246, 0.3); color: #94a3b8; font-family: 'Fira Code', monospace;\">No devices currently detected.</div>", unsafe_allow_html=True)

    st.markdown("<br><hr style='border-color: rgba(255,255,255,0.05);'><br>", unsafe_allow_html=True)

    st.markdown("### 👂 Live DNS Anomaly Feed")
    st.markdown("<p style='color: #94a3b8; margin-bottom: 1rem; font-family: \"Fira Code\", monospace;'>On-Demand telemetry feed.</p>", unsafe_allow_html=True)
    
    if st.session_state.dns_filter_ip:
        f_col1, f_col2 = st.columns([4, 1])
        f_col1.info(f"🔍 **Currently Listening to IP:** `{st.session_state.dns_filter_ip}` (Only showing queries from the last 5 minutes)")
        if f_col2.button("✖️ Stop Listening", use_container_width=True):
            if st.session_state.dns_filter_mac:
                toggle_dns_monitoring(st.session_state.dns_filter_mac, False)
            st.session_state.dns_filter_ip = None
            st.session_state.dns_filter_mac = None
            st.rerun()
            
        display_logs = [log for log in live_dns_logs if log['Source IP'] == st.session_state.dns_filter_ip]
    else:
        display_logs = [] # 🚨 FIX: Shows nothing if no device is targeted

    if display_logs:
        log_col1, log_col2, log_col3, log_col4 = st.columns([1.5, 2, 3, 1.5])
        log_col1.write("**Time**"); log_col2.write("**Source IP**"); log_col3.write("**Query (Target)**"); log_col4.write("**Action**")
        
        for index, log in enumerate(display_logs):
            lc1, lc2, lc3, lc4 = st.columns([1.5, 2, 3, 1.5])
            
            log_time = log['Timestamp']
            if isinstance(log_time, (int, float)) or (isinstance(log_time, str) and log_time.isdigit()):
                log_time = datetime.fromtimestamp(int(log_time), ist).strftime('%H:%M:%S | %d %b')
                
            lc1.markdown(f"<span style='color: #94a3b8; font-family: \"Fira Code\", monospace;'>{log_time}</span>", unsafe_allow_html=True)
            lc2.code(log['Source IP']); lc3.markdown(f"<span style='color: #3b82f6;'>{log['Query']}</span>", unsafe_allow_html=True)
            
            with lc4:
                if st.button("⚡ Terminate", key=f"term_{index}_{log['Source IP']}_{log['Query']}"):
                    offending_mac = None
                    for device in st.session_state.devices:
                        if device['ip'] == log['Source IP']: offending_mac = device['mac']; break
                            
                    if offending_mac:
                        if update_device_status(offending_mac, log['Source IP'], "BLOCKED"):
                            if offending_mac not in st.session_state.blacklist:
                                st.session_state.blacklist.append(offending_mac)
                            st.success(f"⚠️ TARGET ISOLATED.")
                            import time; time.sleep(1.5); st.rerun()
    else:
        if st.session_state.dns_filter_ip:
            st.markdown("<div style=\"padding: 1.5rem; text-align: center; background: rgba(30, 41, 59, 0.4); border-radius: 8px; border: 1px dashed rgba(139, 92, 246, 0.3); color: #94a3b8; font-family: 'Fira Code', monospace;\">Listening... Awaiting new DNS queries from target.</div>", unsafe_allow_html=True)
        else:
            st.markdown("<div style=\"padding: 1.5rem; text-align: center; background: rgba(30, 41, 59, 0.4); border-radius: 8px; border: 1px dashed rgba(139, 92, 246, 0.3); color: #94a3b8; font-family: 'Fira Code', monospace;\">Click '🔍 DNS' on a device above to begin harvesting telemetry.</div>", unsafe_allow_html=True)

    st.button("🔄 Refresh Data Feed", use_container_width=True)

    st.markdown("""
    <div style="text-align: center; margin-top: 3rem; color: #475569; font-size: 0.75rem; font-family: 'Fira Code', monospace; letter-spacing: 0.1em;">
        NETSENTINEL CORE BUILD 1.5.0 • ENCRYPTED CONNECTION • ZERO-TRUST ARCHITECTURE
    </div>
    """, unsafe_allow_html=True)
