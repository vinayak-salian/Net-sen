# 🛡️ NetSen #Real-Time Network Security & Intrusion Detection System

Tech Stack
Endpoint Agent: Python 3, scapy (packet manipulation & ARP spoofing), requests (API synchronization), winreg (host OS registry routing), threading (asynchronous C2 polling).

Cloud API & Logic: AWS API Gateway (REST API), AWS Lambda (Serverless Python / boto3 dispatcher).

State Memory: AWS DynamoDB (NoSQL state management & TTL telemetry logs).

C2 Dashboard: Python, Streamlit (UI framework), pytz / datetime (clock drift mitigation).

Authentication: AWS Cognito (Secure C2 access via User Pools & JWT).

<img width="1919" height="920" alt="image" src="https://github.com/user-attachments/assets/3419ddb0-3a31-4394-a83d-08568ede49d4" />
<LOGIN PAGE>

<img width="1911" height="831" alt="Screenshot 2026-03-18 143139" src="https://github.com/user-attachments/assets/993fadb9-35b3-4ab9-91eb-4ee6d63f69f0" />
< CONTAINMENT ZONE = Blocked devices>
< SESSION QUERIES = TRAFFIC VIEWING OF 'X' DEVICE>

<img width="3026" height="1408" alt="Gemini_Generated_Image_3p893m3p893m3p89" src="https://github.com/user-attachments/assets/79db55e4-2009-480d-a1f6-b3f3cb5fd50f" />
< NOTE THE DEVICE NAME ARE SUPPOSED TO BE  MANUALLY EDITED AS MAC VENDOR LIBRARY USED MIGHT NOT BE ACCURATE ALWAYS WHEN ENACTING TRUST BUTTON HERE WHICH IS ALREADY ENGAGED, IT CAN BE RETRACTED ONCE BLOCKED >

<img width="3538" height="1216" alt="Gemini_Generated_Image_8pked48pked48pke" src="https://github.com/user-attachments/assets/5f789be6-0d4b-4ab1-89ad-9ed710d00917" />
<VIEWS THE TRAFFIC HISTORY OF A DEVICE >


NetSentinel is a zero-trust Network Access Control (NAC) and Endpoint Detection & Response (EDR) system that grants administrators real-time visibility and control over local subnets without requiring physical router access. It solves the problem of unauthorized device management and blind spots in unmanaged networks by deploying a stealthy, Scapy-powered Python agent that synchronizes local network state with a centralized AWS Command & Control (C2) dashboard. This architecture allows security analysts to perform targeted MAC-layer isolation and on-demand DNS telemetry harvesting from anywhere in the world.


Key Features
Distributed Serverless Command & Control (C2): The local agent operates statelessly, synchronizing network deltas with an AWS backend (API Gateway, Lambda, DynamoDB) via asynchronous polling. This decouples the agent from the dashboard, ensuring high availability and secure remote administration authenticated via AWS Cognito.

On-Demand Telemetry Batching: To prevent database flooding and API throttling, the agent uses a "shopping cart" batching methodology. It only captures and uploads DNS traffic for specific endpoints when a targeted "Harvest" command is explicitly issued by the C2 dispatcher.

Automated ARP Containment (Blackholing): Rather than relying on router firewall rules, the agent utilizes targeted ARP spoofing to route unauthorized or suspicious endpoints to a ghost MAC address. This instantly severs the target's internet access at the data link layer (Layer 2).

Smart OUI Vendor Resolution & Caching: Built-in MAC address resolution utilizes a local JSON cache backed by web API fallbacks. This respects public API rate limits, speeds up local discovery, and effectively flags devices utilizing randomized MAC addresses (Privacy OS features).



Challenges & Lessons Learned
1. The "Blackhole" Effect & Network Bridging
The Hurdle: When instructing the agent to intercept DNS traffic using ARP spoofing, the target devices completely lost internet connectivity.

The Cause: By default, host operating systems (like Windows) drop unhandled external network packets rather than forwarding them to the actual gateway. When the agent tricked the target into sending it traffic, those packets died at the agent's network interface.

The Fix: I programmatically modified the Windows Registry (IPEnableRouter) via the Python agent to temporarily enable IP forwarding. This turned the host machine into a seamless, invisible network bridge, allowing telemetry collection without disrupting the target's user experience.

2. Encrypted DNS (DoT/DoH) vs. Legacy Port 53 Sniffing
The Hurdle: The agent successfully harvested DNS queries from Windows and Linux machines, but completely failed to capture browsing data from modern Android and iOS mobile devices.

The Cause: Modern mobile operating systems default to "Private DNS" (DNS over TLS or DNS over HTTPS). This encrypts DNS queries and routes them over TCP ports 853 or 443, bypassing the agent's standard UDP port 53 packet sniffer entirely.

The Lesson: While I temporarily disabled Private DNS on test devices to validate the data pipeline, this limitation highlighted a fundamental shift in modern network security. It proved firsthand why enterprise EDRs can no longer rely purely on passive network sniffing, and must increasingly shift toward endpoint-level SSL decryption (TLS inspection) or direct on-device browser agents to maintain visibility in zero-trust environments.

3. Cloud Clock Drift & "Zombie" Data Filters
The Hurdle: The Streamlit C2 dashboard continuously displayed old, irrelevant DNS queries from days prior when filtering for a specific target's live traffic.

The Cause: AWS DynamoDB retains logs based on a 30-day Time-To-Live (TTL). When the dashboard queried an IP, it pulled the entire historical dataset. Furthermore, slight clock desynchronization (Time Drift) between the local Windows host and the AWS cloud caused new logs to be falsely flagged when applying basic time filters.

The Fix: I implemented a strict "Time Anchor" coupled with a drift buffer in the C2 interface. When an admin initiates a "Harvest" command, the dashboard records the exact UNIX timestamp minus a 60-second drift allowance. The UI then strictly filters the DynamoDB pull, rendering only the telemetry generated after that specific interaction, completely purging "zombie" logs from the view.

4. Host OS Noise & The Case for Dedicated Hardware
The Hurdle: Running the NAC agent on a standard Windows user machine introduced significant latency and "background noise" (mDNS, telemetry, update pings), complicating the packet sniffing filters.

The Lesson: Windows is not optimized to act as a stealth network router. While the architecture functions as a proof-of-concept, deploying this exact Python agent onto a headless Debian environment (like a Raspberry Pi) is the ultimate solution. A Linux kernel handles IP forwarding natively and silently, proving that dedicated, low-cost hardware is vastly superior for local network sentinel deployments.

 Architecture & Data Flow
 ![netsen-flowchart](https://github.com/user-attachments/assets/426e2e57-a882-4ae5-9e75-a8ba102ef368)




 


