import streamlit as st
import pandas as pd
import boto3
from datetime import datetime
import pytz

# --- PAGE CONFIG & CSS (Must be first) ---
st.set_page_config(
    page_title="NetSentinel C&C",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    .stApp {
        background-color: #050505;
        background-image: radial-gradient(circle at 50% 0%, #171124 0%, #050505 50%);
        color: #e2e8f0;
    }

    h1, h2, h3 {
        color: #f8fafc;
        font-weight: 600 !important;
        letter-spacing: -0.025em;
    }
    
    .main-header {
        font-size: 2.5rem;
        background: linear-gradient(90deg, #3b82f6, #8b5cf6, #ec4899);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0rem;
        padding-bottom: 0rem;
        font-weight: 700;
    }
    
    .status-badge {
        display: inline-block;
        padding: 0.35rem 1rem;
        border-radius: 50px;
        background: rgba(16, 185, 129, 0.1);
        border: 1px solid rgba(16, 185, 129, 0.2);
        color: #10b981;
        font-size: 0.875rem;
        font-weight: 500;
        margin-top: 1rem;
        box-shadow: 0 0 15px rgba(16, 185, 129, 0.1);
    }
    
    .cyber-card {
        background: rgba(15, 23, 42, 0.5);
        border: 1px solid rgba(255, 255, 255, 0.05);
        border-radius: 8px; 
        padding: 1.25rem;
        position: relative;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        backdrop-filter: blur(10px);
    }
    .cyber-card::before, .cyber-card::after {
        content: '';
        position: absolute;
        width: 15px; height: 15px;
        border: 2px solid transparent;
        pointer-events: none;
    }
    .cyber-card::before {
        top: -1px; left: -1px;
        border-top-color: var(--card-color);
        border-left-color: var(--card-color);
        border-top-left-radius: 8px;
    }
    .cyber-card::after {
        bottom: -1px; right: -1px;
        border-bottom-color: var(--card-color);
        border-right-color: var(--card-color);
        border-bottom-right-radius: 8px;
    }
    .card-blue { --card-color: #3b82f6; }
    .card-orange { --card-color: #f59e0b; }
    .card-purple { --card-color: #8b5cf6; }
    
    .cyber-card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
    .cyber-card-title { font-size: 0.75rem; color: #cbd5e1; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
    .cyber-card-icon { font-size: 1.2rem; opacity: 0.8; }
    .cyber-card-value { font-size: 2.25rem; font-weight: 700; color: #f8fafc; line-height: 1; font-family: 'Fira Code', monospace; }
    
    .dataframe-container {
        border-radius: 12px;
        overflow: hidden;
        border: 1px solid rgba(255, 255, 255, 0.05);
        background: rgba(15, 23, 42, 0.4);
        backdrop-filter: blur(10px);
    }
    
    table { width: 100%; border-collapse: collapse; font-size: 0.875rem; font-family: 'Fira Code', monospace; color: #cbd5e1; }
    th { text-align: left; padding: 12px 16px; background-color: rgba(30, 41, 59, 0.8); color: #f8fafc; font-weight: 500; text-transform: uppercase; font-size: 0.75rem; border-bottom: 1px solid rgba(255, 255, 255, 0.05); }
    td { padding: 12px 16px; border-bottom: 1px solid rgba(255, 255, 255, 0.02); }
    tr:hover td { background-color: rgba(139, 92, 246, 0.05); }
</style>
""", unsafe_allow_html=True)

# --- 1. AWS CONFIG & FUNCTIONS ---
COGNITO_CLIENT_ID = "f5etbjhkikcoe31g58iqkmv1j"
REGION = "us-east-1"
ist = pytz.timezone('Asia/Kolkata')

def check_aws_auth(username, password):
    try:
        client = boto3.client(
            'cognito-idp', 
            region_name=REGION,
            aws_access_key_id=st.secrets["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=st.secrets["AWS_SECRET_ACCESS_KEY"]
        )
        client.initiate_auth(
            ClientId=COGNITO_CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={'USERNAME': username, 'PASSWORD': password}
        )
        return True, username
    except Exception as e:
        return False, str(e)

def fetch_live_devices():
    try:
        dynamodb = boto3.resource(
            'dynamodb',
            region_name=REGION,
            aws_access_key_id=st.secrets["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=st.secrets["AWS_SECRET_ACCESS_KEY"]
        )
        table = dynamodb.Table('NetSentinel_Data')
        response = table.scan()
        
        formatted_devices = []
        for item in response.get('Items', []):
            formatted_devices.append({
                "mac": item.get('mac_address', 'Unknown'),
                "ip": item.get('ip_address', 'Unknown'),
                "name": item.get('device_name', 'Unknown-Device'),
                "status": item.get('status', 'PENDING'),
                "network": item.get('network_id', 'Unknown-Net')
            })
        return formatted_devices
    except Exception as e:
        st.error(f"DynamoDB Error: {e}")
        return []

def fetch_live_dns():
    try:
        dynamodb = boto3.resource(
            'dynamodb',
            region_name=REGION,
            aws_access_key_id=st.secrets["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=st.secrets["AWS_SECRET_ACCESS_KEY"]
        )
        # Changed from NetSentinel_DNS to NetSentinel_Data
        table = dynamodb.Table('NetSentinel_Data')
        response = table.scan()
        
        logs = []
        for item in response.get('Items', []):
            # Quick filter: Only grab items that actually have DNS data
            # (so we don't accidentally display devices in the DNS table)
            if 'query' in item:
                logs.append({
                    "Timestamp": item.get('timestamp', 'Unknown'),
                    "Source IP": item.get('source_ip', 'Unknown'),
                    "Query": item.get('query', 'Unknown'),
                    "Type": item.get('type', 'Unknown')
                })
        return logs
    except Exception:
        # Fails silently and returns empty array if table doesn't exist yet
        return []
def create_card(title, value, icon, color_class):
    html = f"""
    <div class="cyber-card {color_class}">
        <div class="cyber-card-header">
            <span class="cyber-card-title">{title}</span>
            <span class="cyber-card-icon">{icon}</span>
        </div>
        <div class="cyber-card-body">
            <span class="cyber-card-value">{value}</span>
        </div>
    </div>
    """
    return html

# --- 2. SESSION STATE INITIALIZATION ---
if "authentication_status" not in st.session_state:
    st.session_state["authentication_status"] = None
if "name" not in st.session_state:
    st.session_state["name"] = None
if 'blacklist' not in st.session_state:
    st.session_state.blacklist = []
if 'devices' not in st.session_state:
    st.session_state.devices = []

# --- 3. RENDER LOGIN ---
if st.session_state["authentication_status"] is not True:
    st.markdown('<div class="main-header" style="text-align: center; margin-top: 10vh;">NetSentinel Login</div>', unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        with st.form("Login"):
            username = st.text_input("Email/Username")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Authenticate")
            
            if submit:
                success, info = check_aws_auth(username, password)
                if success:
                    st.session_state["authentication_status"] = True
                    st.session_state["name"] = info
                    st.rerun()
                else:
                    st.session_state["authentication_status"] = False
                    st.error(f"Login failed: {info}")

# --- 4. SHOW DASHBOARD ---
if st.session_state["authentication_status"] is True:
    
    # 🚨 ONLY FETCHING LIVE DATA NOW
    st.session_state.devices = fetch_live_devices()
    live_dns_logs = fetch_live_dns()
    
    # Header Section
    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown('<div class="main-header">NetSentinel Command & Control</div>', unsafe_allow_html=True)
        st.markdown('<div class="status-badge">🟢 AGENT OPERATIONAL • SECURE LINK</div>', unsafe_allow_html=True)
    with col2:
        st.markdown(
            f"""
            <div style="text-align: right; padding-top: 1rem; color: #94a3b8; font-family: 'Fira Code', monospace;">
                <div>SYS_TIME // {datetime.now(ist).strftime('%H:%M:%S IST')}</div>
                <div>ADMIN // {st.session_state['name']}</div>
            </div>
            """, unsafe_allow_html=True
        )
        if st.button("Terminate Session (Logout)", use_container_width=True):
            st.session_state["authentication_status"] = None
            st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    # Metric Cards
    m1, m2, m3 = st.columns(3)
    with m1:
        st.markdown(create_card("LIVE DEVICES", len(st.session_state.devices), "📡", "card-blue"), unsafe_allow_html=True)
    with m2:
        st.markdown(create_card("CONTAINMENT ZONE", len(st.session_state.blacklist), "🚫", "card-orange"), unsafe_allow_html=True)
    with m3:
        st.markdown(create_card("DNS QUERIES", len(live_dns_logs), "🔗", "card-purple"), unsafe_allow_html=True)

    st.markdown("<br><hr style='border-color: rgba(255,255,255,0.05);'><br>", unsafe_allow_html=True)

    # Active Blacklist Section
    st.markdown("### 🚫 Active Mitigation (Blacklist)")
    if st.session_state.blacklist:
        for mac in st.session_state.blacklist:
            b_col1, b_col2 = st.columns([4, 1])
            b_col1.error(f"BLOCKED MAC: `{mac}` - Routing to void.")
            if b_col2.button("Unblock", key=f"unblock_{mac}"):
                st.session_state.blacklist.remove(mac)
                st.rerun()
    else:
        st.markdown("""
        <div style="padding: 1.5rem; text-align: center; background: rgba(30, 41, 59, 0.4); border-radius: 12px; border: 1px dashed rgba(255,255,255,0.1); color: #94a3b8;">
            Containment zone is currently empty. No entities actively banned.
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Live Network Status Table
    st.markdown("### 📡 Live Network Status")
    
    if len(st.session_state.devices) > 0:
        h1, h2, h3, h4, h5 = st.columns([2, 2, 2, 1, 2])
        h1.write("**Device Name**")
        h2.write("**MAC Address**")
        h3.write("**IP Address**")
        h4.write("**Status**")
        h5.write("**Action**")

        for index, row in enumerate(st.session_state.devices):
            if row['mac'] in st.session_state.blacklist:
                continue
                
            c1, c2, c3, c4, c5 = st.columns([2, 2, 2, 1, 2])
            c1.write(f"**{row['name']}**")
            c2.code(row['mac'])
            c3.code(row['ip'])
            
            with c4:
                if row['status'] == "TRUSTED":
                    st.markdown("<span style='color: #10b981; font-weight: bold;'>TRUSTED</span>", unsafe_allow_html=True)
                else:
                    st.markdown("<span style='color: #f59e0b; font-weight: bold;'>PENDING</span>", unsafe_allow_html=True)
                    
            with c5:
                btn_col1, btn_col2 = st.columns(2)
                if row['status'] == "PENDING":
                    if btn_col1.button("✅ Trust", key=f"t_{index}"):
                        pass
                else:
                    btn_col1.button("Done", disabled=True, key=f"v_{index}")
                
                if btn_col2.button("🚫 Block", key=f"b_{index}"):
                    st.session_state.blacklist.append(row['mac'])
                    st.rerun()
    else:
        st.markdown("""
        <div style="padding: 1.5rem; text-align: center; background: rgba(30, 41, 59, 0.4); border-radius: 12px; border: 1px dashed rgba(255,255,255,0.1); color: #94a3b8;">
            No devices currently detected in the network.
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br><hr style='border-color: rgba(255,255,255,0.05);'><br>", unsafe_allow_html=True)

    # Traffic Hearing (LIVE FETCH)
    st.markdown("### 👂 Live DNS Anomaly Feed")
    st.markdown("<p style='color: #94a3b8; margin-bottom: 1rem;'>Real-time interception of DNS queries.</p>", unsafe_allow_html=True)
    
    if live_dns_logs:
        df_dns = pd.DataFrame(live_dns_logs)
        html_table = f'<div class="dataframe-container">{df_dns.to_html(index=False, classes="custom-table")}</div>'
        st.markdown(html_table, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="padding: 1.5rem; text-align: center; background: rgba(30, 41, 59, 0.4); border-radius: 12px; border: 1px dashed rgba(255,255,255,0.1); color: #94a3b8;">
            Awaiting live DNS telemetry. No queries intercepted yet.
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""
    <div style="text-align: center; margin-top: 3rem; color: #475569; font-size: 0.875rem; font-family: 'Fira Code', monospace;">
        NETSENTINEL CORE BUILD 1.5.0 • ENCRYPTED CONNECTION • ZERO-TRUST ARCHITECTURE
    </div>
    """, unsafe_allow_html=True)
