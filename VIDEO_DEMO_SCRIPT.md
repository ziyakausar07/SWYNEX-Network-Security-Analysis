# 🎥 Video Explanation & Demo Script (1.5 – 2 Minutes)
## Task 2: Network Security Analysis Using Wireshark
**Intern:** Ziyakausar Tamboli (Intern ID: `SWX-2026-002678`)  
**Organization:** SWYNEX Technologies — Cyber Security Internship

---

### 🎙️ Recording Guidelines
- **Duration:** 1.5 to 2 minutes.
- **Recording Tool:** OBS Studio, Windows Game Bar (`Win + G`), Loom, or Clipchamp.
- **What to show on screen:** Share your screen showing Wireshark or opening the images in your `evidence/` folder as you speak.
- **Tone:** Clear, confident, and professional.

---

### 📜 Spoken Script

#### **[0:00 – 0:25] Introduction**
> *"Hello everyone! My name is Ziyakausar Tamboli, and I am currently a Cyber Security Intern at SWYNEX Technologies with Intern ID SWX-2026-002678.*  
> *Today, I will be presenting my work and findings for Task 2: Network Security Analysis Using Wireshark.*  
> *In this task, my objective was to capture and inspect live network traffic, analyze the protocol hierarchy, inspect TCP and TLS sessions, and formulate defensive security recommendations."*

*(Screen Action: Show your GitHub repository README or Wireshark main window).*

---

#### **[0:25 – 0:50] Protocol Hierarchy & Conversations**
> *"First, I analyzed the Protocol Hierarchy of the captured network traffic.*  
> *Looking at our statistics, IPv6 accounted for nearly 95% of routed packets, reflecting modern dual-stack network communication. Crucially, Transport Layer Security (TLS) constituted over 71% of the total network byte volume, showing that application data is heavily encrypted.*  
> *In the conversations table across Layer 2 and Layer 3, I observed standard communication between my local interface and the default gateway, alongside background discovery protocols such as mDNS and SSDP."*

*(Screen Action: Open `evidence/02_protocol_hierarchy_statistics.png` and `evidence/06_conversations_tcp_sessions.png`).*

---

#### **[0:50 – 1:20] TCP Handshake & TLS Inspection**
> *"Next, I used Wireshark display filters to examine connection establishment and security.*  
> *By applying the filter `tcp.flags.syn == 1 && tcp.flags.ack == 0`, I isolated the initial TCP synchronization packet destined for port 443. The packet demonstrated standard initial sequence numbers, window scaling of 256, and selective acknowledgments.*  
> *Applying the `tls` display filter revealed the complete TLS 1.3 handshake. Inspecting the Client Hello packet revealed the Server Name Indication (SNI) for Microsoft cloud telemetry (`mobile.events.data.microsoft.com`) and security endpoints (`api1.reasonsecurity.com`).*  
> *Using the Follow TCP Stream feature, I verified that the payload was completely encrypted, ensuring zero plaintext exposure of credentials or session tokens on the wire."*

*(Screen Action: Open `evidence/09_tcp_syn_packet_details.png`, `evidence/10_filter_tls_handshake_sni.png`, and `evidence/11_follow_tcp_stream_encrypted_payload.png`).*

---

#### **[1:20 – 1:45] Defensive Recommendations & Hardening**
> *"From a defensive perspective, I identified key preventative measures:*  
> *1. Enforcing strict outbound egress filtering to block sensitive database ports like Redis 6379.*  
> *2. Disabling unnecessary local broadcast discovery like SSDP and UPnP on enterprise endpoints.*  
> *3. Mandating TLS 1.3 with forward secrecy across all internal and external communication.*  
> *4. Implementing SNI deep packet inspection and intrusion detection alerting using Snort or Suricata."*

*(Screen Action: Show Section 10 of `report/Network_Security_Analysis_Report.md` or `README.md`).*

---

#### **[1:45 – 2:00] Conclusion & Wrap-up**
> *"In conclusion, this analysis verified that our network traffic maintains strong cryptographic protections while highlighting important network hygiene practices.*  
> *My complete technical report and evidence files are available on my GitHub repository.*  
> *Thank you to SWYNEX Technologies for this incredible hands-on internship experience!"*

---

### 💡 Quick Tips:
- If you don't want to show your webcam, just record your screen with your voiceover.
- Keep the screenshots queued up in your image viewer so you can easily press the right arrow key to transition smoothly between them.
