import streamlit as st
import pandas as pd
import boto3  # <-- NEW: For AWS Integration
from datetime import datetime
# --- 1. AWS COGNITO CONFIG ---
# Replace with your actual IDs
COGNITO_CLIENT_ID = "f5etbjhkikcoe31g58iqkmv1j"
REGION = "us-east-1"

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
        
        # Format the data to match what our dashboard expects
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

# --- 2. SESSION STATE INITIALIZATION ---
if st.session_state["authentication_status"] is not True:
    st.title("🛡️ NetSentinel Login")
    with st.form("Login"):
        u = st.text_input("Email")
        p = st.text_input("Password", type="password")
        if st.form_submit_button("Login"):
            res, msg = check_aws_auth(u, p)
            if res:
                st.session_state["authentication_status"] = True
                st.session_state["name"] = msg
                st.rerun()
            else:
                st.error(f"Login failed: {msg}")

# --- 3. RENDER LOGIN (Cognito Style) ---
if st.session_state["authentication_status"] is not True:
    st.title("🛡️ NetSentinel Login")
    with st.form("Login"):
        username = st.text_input("Email/Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
        
        if submit:
            success, info = check_aws_auth(username, password)
            if success:
                st.session_state["authentication_status"] = True
                st.session_state["name"] = info
                st.rerun()
            else:
                st.session_state["authentication_status"] = False
                st.error(f"Login failed: {info}")

# --- 4. SHOW DASHBOARD (Original Features Preserved) ---
if st.session_state["authentication_status"] is True:
    
    with st.sidebar:
        st.write(f"Logged in as: **{st.session_state['name']}**")
        if st.button("Logout"):
            st.session_state["authentication_status"] = None
            st.session_state["name"] = None
            st.rerun()
    
    st.title("🛡️ NetSentinel: King Admin")
    st.caption("Cross-Platform Security Command & Control")

   
   st.session_state.devices = fetch_live_devices()
    
    if 'blacklist' not in st.session_state:
        st.session_state.blacklist = []

    # PRESERVED: TOP ROW: BLACKLIST
    with st.expander("🚫 Active Blacklist"):
        if st.session_state.blacklist:
            for mac in st.session_state.blacklist:
                b_col1, b_col2 = st.columns([3, 1])
                b_col1.error(f"BLOCKED: `{mac}`")
                if b_col2.button("Unblock", key=f"unblock_{mac}"):
                    st.session_state.blacklist.remove(mac)
                    st.rerun()
        else:
            st.info("No devices currently black-holed.")

    st.markdown("---")

    # PRESERVED: DEVICE MANAGEMENT TABLE
    st.subheader("📡 Live Network Status")
    
    h1, h2, h3, h4, h5 = st.columns([2, 2, 2, 1, 2])
    h1.write("**Device**")
    h2.write("**MAC Address**")
    h3.write("**IP**")
    h4.write("**Status**")
    h5.write("**Action**")

    for index, row in enumerate(st.session_state.devices):
        if row['mac'] in st.session_state.blacklist:
            continue
            
        c1, c2, c3, c4, c5 = st.columns([2, 2, 2, 1, 2])
        c1.write(f"**{row['name']}**")
        c2.code(row['mac'])
        c3.write(row['ip'])
        
        with c4:
            if row['status'] == "TRUSTED":
                st.success("Trusted")
            else:
                st.warning("Pending")
                
        with c5:
            btn_col1, btn_col2 = st.columns(2)
            if row['status'] == "PENDING":
                if btn_col1.button("✅ Trust", key=f"t_{index}"):
                    st.session_state.devices[index]['status'] = "TRUSTED"
                    st.rerun()
            else:
                btn_col1.button("Done", disabled=True, key=f"v_{index}")
            
            if btn_col2.button("🚫 Block", key=f"b_{index}"):
                st.session_state.blacklist.append(row['mac'])
                st.rerun()

    # PRESERVED: TRAFFIC HEARING
    st.markdown("---")
    st.subheader("👂 Traffic Hearing (DNS Logs)")
    mock_logs = [{"Time": "23:05", "Device": "IoT-Device", "Domain": "api.tracker.com"}]
    st.table(pd.DataFrame(mock_logs))
