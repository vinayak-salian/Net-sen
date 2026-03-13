import streamlit as st
import streamlit_authenticator as stauth
import pandas as pd

# --- 1. USER AUTHENTICATION CONFIG ---
credentials = {
    "usernames": {
        "vinayak": {
            "name": "Vinayak Salian",
            "password": "$2b$12$F1s0O7L4fUZ1RrFS.hN0JeGE6x1xRgLT5mChPP5H7oaFoaep5UC3W" 
        }
    }
}

authenticator = stauth.Authenticate(
    credentials=credentials,
    cookie_name="netsentinel_cookie",
    key="auth_key",
    cookie_expiry_days=30
)

# --- 2. RENDER LOGIN ---
authenticator.login(location='main')

if st.session_state["authentication_status"]:
    # --- AUTHENTICATED: SHOW DASHBOARD ---
    with st.sidebar:
        st.write(f"Logged in as: **{st.session_state['name']}**")
        authenticator.logout('Logout', 'sidebar')
    
    st.title("🛡️ NetSentinel: King Admin")
    st.caption("Cross-Platform Security Command & Control")

    # Initialize session state for mock data
    if 'devices' not in st.session_state:
        st.session_state.devices = [
            {"mac": "1a:8e:8d:01:02:03", "ip": "192.168.1.5", "name": "HP-Victus", "status": "TRUSTED"},
            {"mac": "f4:06:12:ab:cd:ef", "ip": "192.168.1.12", "name": "Unknown-Mobile", "status": "PENDING"},
            {"mac": "00:de:ad:be:ef:01", "ip": "192.168.1.20", "name": "IoT-Device", "status": "PENDING"}
        ]
    if 'blacklist' not in st.session_state:
        st.session_state.blacklist = []

    # --- TOP ROW: BLACKLIST ---
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

    # --- DEVICE MANAGEMENT TABLE ---
    st.subheader("📡 Live Network Status")
    
    # Headers
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

    # --- TRAFFIC HEARING ---
    st.markdown("---")
    st.subheader("👂 Traffic Hearing (DNS Logs)")
    mock_logs = [{"Time": "23:05", "Device": "IoT-Device", "Domain": "api.tracker.com"}]
    st.table(pd.DataFrame(mock_logs))

elif st.session_state["authentication_status"] is False:
    st.error('Username/password is incorrect')
elif st.session_state["authentication_status"] is None:
    st.warning('Please enter your credentials')