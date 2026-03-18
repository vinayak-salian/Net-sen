import os
import sys
import winreg
import ctypes
import time
import json
import socket
import threading
import requests
from win10toast import ToastNotifier
from scapy.all import ARP, Ether, srp, conf, IP, UDP, DNS, DNSQR, send, sniff, sendp

# --- VENDOR LOOKUP INITIALIZATION ---
try:
    from mac_vendor_lookup import MacLookup
    mac_lookup = MacLookup()
    try:
        # Attempts to update the local database on first run
        mac_lookup.update_vendors()
    except:
        pass
except ImportError:
    print("[!] ERROR: Run 'pip install mac-vendor-lookup' to enable hardware identification.")

# --- CONSTANTS & DIRECTORIES ---
BASE_DIR = r"C:\NetSen"
LOG_PATH = os.path.join(BASE_DIR, "scan_log.txt")
TRUSTED_PATH = os.path.join(BASE_DIR, "trusted.json")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json") 
VENDOR_CACHE_PATH = os.path.join(BASE_DIR, "vendor_cache.json")

# 🚨 GITHUB NOTICE: API URL and Subnets are now managed via config.json for security.
# Default placeholders below are overwritten by load_config()
CLOUD_URL = "https://YOUR-API-ID.execute-api.us-east-1.amazonaws.com" 
AUTHORIZED_SUBNETS = ["192.168.1.0/24"] 

# --- GLOBAL STATE ---
current_state = {}       
LAST_KNOWN_STATE = {} 
missing_count = {}
blacklist = []  
hearing_list = [] 
cached_access_token = None
pending_dns_logs = []

# --- CORE UTILITIES ---

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

def elevate():
    script = os.path.abspath(sys.argv[0])
    params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)

def add_to_startup():
    pth = sys.executable
    pythonw = pth.replace("python.exe", "pythonw.exe")
    script_path = os.path.realpath(__file__)
    launch_cmd = f'"{pythonw}" "{script_path}"'
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
            winreg.SetValueEx(key, "NetSentinelAgent", 0, winreg.REG_SZ, launch_cmd)
    except: pass

def get_hostname(ip):
    try: return socket.gethostbyaddr(ip)[0]
    except: return "Unknown-Device"

def enable_ip_routing():
    """Enables Windows IP Forwarding to prevent target connection drops during interception."""
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
    except: pass

def get_device_vendor(mac_address):
    """Resolves MAC to Vendor using local cache and offline database."""
    try:
        first_octet = int(mac_address.replace(':', '')[0:2], 16)
        if first_octet & 0b00000010: return "Randomized (Privacy OS)"
    except: pass
    
    cache = {}
    if os.path.exists(VENDOR_CACHE_PATH):
        try:
            with open(VENDOR_CACHE_PATH, "r") as f: cache = json.load(f)
        except: pass
    
    if mac_address in cache: return cache[mac_address]

    try:
        vendor = mac_lookup.lookup(mac_address)
        if vendor:
            cache[mac_address] = vendor[:25]
            with open(VENDOR_CACHE_PATH, "w") as f: json.dump(cache, f)
            return vendor[:25]
    except: pass
    return None

# --- AUTH & CONFIG MANAGER ---

def load_config():
    """Loads environment-specific variables. Essential for open-source portability."""
    global CLOUD_URL, AUTHORIZED_SUBNETS
    if not os.path.exists(CONFIG_PATH):
        default_conf = {
            "api_url": "https://YOUR-API-ID.execute-api.us-east-1.amazonaws.com",
            "authorized_subnets": ["192.168.1.0/24"],
            "refresh_token": "", 
            "network_name": "Primary-Lab",
            "client_id": "YOUR_COGNITO_CLIENT_ID" 
        }
        if not os.path.exists(BASE_DIR): os.makedirs(BASE_DIR)
        with open(CONFIG_PATH, "w") as f: json.dump(default_conf, f, indent=4)
        return default_conf
    
    with open(CONFIG_PATH, "r") as f:
        conf_data = json.load(f)
        CLOUD_URL = conf_data.get("api_url", CLOUD_URL)
        AUTHORIZED_SUBNETS = conf_data.get("authorized_subnets", AUTHORIZED_SUBNETS)
        return conf_data

def get_access_token():
    global cached_access_token
    config = load_config()
    if not config["refresh_token"]: return None
    # For GitHub version, return the cached token or 'EXPIRED' to signal a refresh is needed
    return cached_access_token if cached_access_token else "EXPIRED"

# --- CLOUD SYNC ---

def sync_with_cloud():
    global blacklist, hearing_list, current_state, LAST_KNOWN_STATE, pending_dns_logs
    config = load_config()
    toaster = ToastNotifier()
    notified_unauthorized = False 

    while True:
        token = get_access_token()
        if token:
            try:
                target_range, _ = get_automatic_subnet()
                
                if target_range not in AUTHORIZED_SUBNETS:
                    if not notified_unauthorized:
                        toaster.show_toast("NetSentinel Alert", f"Unauthorized Network: {target_range}. Sync paused.", duration=5, threaded=True)
                        notified_unauthorized = True
                    time.sleep(10)
                    continue 
                
                notified_unauthorized = False
                state_changed = (current_state != LAST_KNOWN_STATE)
                
                if state_changed: 
                    LAST_KNOWN_STATE = current_state.copy()
                
                trusted_data = {}
                if os.path.exists(TRUSTED_PATH):
                    with open(TRUSTED_PATH, "r") as f: trusted_data = json.load(f)
                
                enriched_devices = {}
                for mac, device_data in current_state.items():
                    ip = device_data.get('ip', device_data) if isinstance(device_data, dict) else device_data
                    name = trusted_data.get(mac, {}).get("name", "Unknown-Device")
                    enriched_devices[mac] = {"ip": ip, "name": name}

                logs_to_send = pending_dns_logs[:]
                pending_dns_logs.clear()

                payload = {
                    "network_id": config["network_name"],
                    "subnet": target_range,
                    "devices": enriched_devices, 
                    "dns_logs": logs_to_send, 
                    "timestamp": time.time()
                }
                
                headers = {"Authorization": f"Bearer {token}"}
                response = requests.post(CLOUD_URL + "/heartbeat", json=payload, headers=headers, timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    blacklist = data.get("blacklist", [])
                    hearing_list = data.get("hearing_list", [])
            except: pass
                
        time.sleep(10) 

# --- TRAFFIC HEARING (C2 LISTENER) ---

def traffic_hearing():
    global pending_dns_logs, hearing_list, current_state
    seen_dns_queries = set()
    
    def dns_monitor(pkt):
        if pkt.haslayer(DNSQR):
            src_ip = pkt[IP].src
            
            target_mac = None
            for mac, device_data in current_state.items():
                actual_ip = device_data.get('ip') if isinstance(device_data, dict) else device_data
                if actual_ip == src_ip:
                    target_mac = mac
                    break
            
            if not target_mac or target_mac not in hearing_list: return 

            query = pkt[DNSQR].qname.decode('utf-8')
            if query.endswith('.'): query = query[:-1]
            
            query_signature = f"{src_ip}-{query}"
            if query_signature not in seen_dns_queries:
                seen_dns_queries.add(query_signature)
                pending_dns_logs.append({
                    "source_ip": src_ip, "query": query, "type": "A", "timestamp": int(time.time())
                })

    def dns_pointer():
        while True:
            if hearing_list:
                target_range, iface = get_automatic_subnet()
                router_ip = target_range.replace(".0/24", ".1")
                for target_mac in hearing_list:
                    device_data = current_state.get(target_mac)
                    target_ip = device_data.get('ip') if isinstance(device_data, dict) else device_data
                    if target_ip:
                        pkg = Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip)
                        sendp(pkg, verbose=False, iface=iface)
            time.sleep(3)

    threading.Thread(target=dns_pointer, daemon=True).start()
    sniff(filter="udp port 53", prn=dns_monitor, store=0)

def block_enforcer():
    GHOST_MAC = "0a:de:ad:be:ef:00" 
    while True:
        if blacklist:
            target_range, iface = get_automatic_subnet()
            router_ip = target_range.replace(".0/24", ".1")
            for target_mac in blacklist:
                device_data = current_state.get(target_mac)
                target_ip = device_data.get('ip') if isinstance(device_data, dict) else device_data
                if target_ip:
                    pkg = Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip, hwsrc=GHOST_MAC)
                    sendp(pkg, verbose=False, iface=iface)
        time.sleep(1.5)

def manage_trusted_json(found_devices):
    trusted_data = {}
    if os.path.exists(TRUSTED_PATH):
        try:
            with open(TRUSTED_PATH, "r") as f: trusted_data = json.load(f)
        except: pass
        
    updated = False
    for mac, device_data in found_devices.items():
        ip = device_data.get('ip') if isinstance(device_data, dict) else device_data
        if mac not in trusted_data:
            name = get_device_vendor(mac)
            if not name: name = get_hostname(ip)
            trusted_data[mac] = {"name": name, "last_ip": ip, "status": "trusted"}
            updated = True
            
    if updated:
        with open(TRUSTED_PATH, "w") as f: json.dump(trusted_data, f, indent=4)
    return trusted_data

def get_automatic_subnet():
    try:
        for route in sorted(conf.route.routes, key=lambda x: x[5]):
            if route[0] == 0 and route[1] == 0 and not route[4].startswith('127.'):
                return ".".join(route[4].split('.')[:-1]) + ".0/24", route[3]
    except: pass
    return "192.168.1.0/24", None

def wake_up_devices(iface):
    try:
        mdns_pkt = IP(dst="224.0.0.251")/UDP(sport=5353, dport=5353)/DNS(rd=1, qd=DNSQR(qname="_services._dns-sd._udp.local"))
        send(mdns_pkt, verbose=False, iface=iface, count=2)
    except: pass

def perform_robust_scan(target_range, active_iface):
    try:
        wake_up_devices(active_iface)
        time.sleep(3)
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_range), timeout=8, retry=4, verbose=False, iface=active_iface)
        return {r.hwsrc: r.psrc for s, r in ans}
    except: return {}

def monitor_network():
    global current_state, missing_count
    target_range, active_iface = get_automatic_subnet()
    scanned_devices = perform_robust_scan(target_range, active_iface)
    manage_trusted_json(scanned_devices)
    
    scanned_macs = set(scanned_devices.keys())
    known_macs = set(current_state.keys())
    new_arrivals = scanned_macs - known_macs

    for mac in scanned_macs:
        missing_count[mac] = 0
        if mac in new_arrivals: current_state[mac] = scanned_devices[mac]

    for mac in (known_macs - scanned_macs):
        missing_count[mac] = missing_count.get(mac, 0) + 1
        if missing_count[mac] >= 3:
            if mac in current_state: del current_state[mac]
            if mac in missing_count: del missing_count[mac]

if __name__ == "__main__":
    if not is_admin():
        elevate(); sys.exit()

    if not os.path.exists(BASE_DIR): os.makedirs(BASE_DIR)

    enable_ip_routing() 
    add_to_startup()
    load_config() 

    target, iface = get_automatic_subnet()
    current_state = perform_robust_scan(target, iface)
    manage_trusted_json(current_state)

    threading.Thread(target=sync_with_cloud, daemon=True).start()
    threading.Thread(target=traffic_hearing, daemon=True).start()
    threading.Thread(target=block_enforcer, daemon=True).start()

    while True:
        monitor_network()
        time.sleep(30)
