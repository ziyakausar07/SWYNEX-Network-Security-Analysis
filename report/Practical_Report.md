# NETWORK SECURITY ANALYSIS USING WIRESHARK

## Practical Report

**Student Name:** Ziyakausar J. Tamboli  
**Internship / Program:** Cyber Security Internship  
**Host Organization:** SWYNEX Technologies  
**Intern ID:** `SWX-2026-002678`  
**Tool Used:** Wireshark Network Protocol Analyzer (v4.6.x)  
**Analysis Type:** Packet Capture & Display-Filter Analysis  
**Repository:** [SWYNEX-Network-Security-Analysis](https://github.com/ziyakausar07/SWYNEX-Network-Security-Analysis)  
**Video Demonstration:** `Network Security Analysis.mp4` (Duration: 5m 20s)  

---

### 1. Introduction

Wireshark is a world-standard network protocol analyzer used to inspect packets captured from a live network interface or loaded from saved packet capture files (`.pcap` / `.pcapng`). This practical involved examining protocol distribution across the OSI model, auditing TCP conversations, investigating unencrypted HTTP and conventional DNS traffic, dissecting TLS cryptographic handshake records (TLS 1.2 and TLS 1.3), verifying encrypted application data streams, and auditing selected TCP analysis flags (SYN, ACK, FIN, RST, retransmissions, and duplicate acknowledgments). 

Targeted Wireshark display filters were systematically applied to isolate specific packet types without modifying or dropping any frames from the underlying capture files.

---

### 2. Objectives

The core objectives of this practical investigation were:
1. **Protocol Hierarchy Inspection:** Inspect the distribution and volumetric share of protocols across Data Link, Network, Transport, and Application layers.
2. **Conversation Auditing:** Review TCP conversations and communications utilizing destination port 443 (HTTPS/TLS).
3. **Cleartext Protocol Check:** Test for visible unencrypted HTTP (`http`) and conventional DNS (`dns` on UDP port 53) packets.
4. **Cryptographic Handshake Dissection:** Examine TLS handshake messages (Client Hello, Server Hello), Server Name Indication (SNI), offered cipher suites, and negotiated parameters.
5. **Payload Confidentiality Verification:** Inspect TLS Application Data records and reconstruct TCP streams to verify encryption integrity.
6. **TCP Anomaly & Flag Auditing:** Check the capture for TCP retransmissions (`tcp.analysis.retransmission`), duplicate acknowledgments (`tcp.analysis.duplicate_ack`), connection termination (`tcp.flags.fin == 1`), and connection resets (`tcp.flags.reset == 1`).
7. **Empirical Evidence Correlation:** Cross-verify observations across two distinct captures (the detailed Home Baseline Capture and the College Live Video Demonstration Capture) and document findings strictly within the limits of packet-level evidence.

---

### 3. Tools and Method

The analysis was executed using Wireshark on a Windows 11 workstation. The workflow utilized the following analytical features:
- **Interface Capture:** Live traffic was captured on the active Wi-Fi interface.
- **Statistics Menu:**
  - `Statistics -> Protocol Hierarchy`: Used to generate packet and byte distribution percentages.
  - `Statistics -> Conversations`: Used to inspect Layer 2 Ethernet, Layer 3 IPv4/IPv6, and Layer 4 TCP/UDP session matrices.
- **Display Filter Bar:** Boolean and protocol-specific display filters were entered sequentially to focus on target frames. These filters alter which packets are displayed in the packet list pane without deleting or altering underlying packet data.
- **Packet Details & Bytes Panes:** Tree-based protocol dissection of Ethernet frames, IP headers, TCP control flags, and TLS extension records.
- **Follow TCP Stream:** Reassembly of serialized bidirectional application byte streams.

---

### 4. Observations and Results

The practical evaluated two complementary datasets:
- **Dataset A (Home Baseline & Endpoint Dissection):** Recorded in baseline captures `wireshark_Wi-FiFH69W3.pcapng` (134 frames) and `wireshark_Wi-FiPOLDX3.pcapng` (122 frames).
- **Dataset B (College Live Video Demonstration):** Captured live in `Network Security Analysis.mp4` under file reference `wireshark_Wi-FiCIHYX3.pcapng` (3,519 frames).

#### Comprehensive Observation Table

| No. | Analysis Category | Filter / Location | Observed Result (Home Baseline) | Observed Result (Video Demonstration) | Technical Interpretation & Defensive Context | Evidence Reference |
|:---:|:---|:---|:---|:---|:---|:---|
| **1** | **Protocol Hierarchy** | `Statistics → Protocol Hierarchy` | **IPv6:** 94.8% of frames (127 pkts)<br>**TLS:** 71.3% of bytes (24,184 B) | **IPv6:** 99.9% of frames (3,517 pkts)<br>**TLS:** 85.7% of bytes (2,595,382 B) | IPv6 represents the dominant routed network protocol. TLS represents the vast majority of transmitted byte volume, confirming application data is routed through encrypted tunnels. | `evidence/02_protocol_hierarchy_statistics.png`<br>`evidence/video_demonstration/video_03_protocol_hierarchy_statistics.png` |
| **2** | **TCP Conversations** | `Statistics → Conversations → TCP` | **12 conversations / streams**; all inspected streams targeted **Port 443** | **4 conversations / streams**; all targeted **Port 443** | Ephemeral high-range client ports connect to external HTTPS (port 443) services (Cloudflare CDN, Google Edge, Microsoft Azure). Port 443 indicates HTTPS convention. | `evidence/06_conversations_tcp_sessions.png`<br>`evidence/video_demonstration/video_02_conversations_tcp_streams.png` |
| **3** | **IPv6 Traffic** | `ipv6` | 127 matching packets displayed | 3,517 matching packets displayed | Isolates IPv6 traffic. Enables inspection of 128-bit source/destination addresses and encapsulated TCP/UDP payload headers. | `evidence/05_conversations_ipv6.png`<br>`evidence/video_demonstration/video_03_protocol_hierarchy_statistics.png` |
| **4** | **TCP Port 443** | `tcp.port == 443` | 117 matching packets displayed | 3,517 matching packets displayed | Isolates traffic utilizing TCP port 443, commonly assigned to TLS/HTTPS communications. | `evidence/06_conversations_tcp_sessions.png`<br>`evidence/video_demonstration/video_02_conversations_tcp_streams.png` |
| **5** | **HTTP Filter** | `http` | **0 packets matched (0.0%)** | **0 packets matched (0.0%)** | Wireshark identified zero cleartext HTTP packets. Modern web applications and background services avoid unencrypted HTTP, preventing plain-text interception. | `evidence/video_demonstration/video_04_display_filter_http_zero_match.png` |
| **6** | **DNS Filter** | `dns` | **0 packets matched (0.0%)** | **0 packets matched (0.0%)** | Zero conventional unencrypted DNS packets identified on UDP port 53. Indicates DNS queries were served by local OS cache or encrypted via DNS-over-HTTPS (DoH). | `evidence/video_demonstration/video_05_display_filter_dns_zero_match.png` |
| **7** | **TLS Traffic** | `tls` | 49 matching packets displayed | 671 matching packets displayed | Displays TLS record headers. In the video capture, displays TLSv1.2 records including Application Data, Ignored Unknown Record, and TCP Fast Retransmissions. | `evidence/10_filter_tls_handshake_sni.png`<br>`evidence/video_demonstration/video_06_display_filter_tls_fast_retransmission.png` |
| **8** | **TLS Handshake** | `tls.handshake` | **2 packets matched:** Frame 6 (Client Hello) & Frame 7 (Server Hello) | **3 packets matched:** Frames 1880, 3128, 3289 (Encrypted Handshake Messages) | Handshake details show cryptographic negotiation. Home capture captured initial connection setup; college video capture captured post-handshake / session-resumption records. | `evidence/10_filter_tls_handshake_sni.png`<br>`evidence/video_demonstration/video_07_display_filter_tls_handshake_messages.png` |
| **9** | **Client Hello** | `tls.handshake.type == 1` | **Frame 6 matched:** SNI `mobile.events.data.microsoft.com`, 20 offered ciphers | **0 packets matched** in video capture slice | Client Hello initiates TLS parameter negotiation. It was captured in the home baseline endpoint session (`40.79.141.157`) but not in the video capture window. | `evidence/12_client_hello_detailed_parameters.png`<br>`evidence/video_demonstration/video_08_display_filter_client_hello_type1.png` |
| **10** | **Server Hello** | `tls.handshake.type == 2` | **Frame 7 matched:** Selected cipher `TLS_AES_256_GCM_SHA384`, TLS 1.3 | **0 packets matched** in video capture slice | Server Hello communicates the chosen TLS version and cipher suite. Verified in the home baseline endpoint session. | `evidence/13_server_hello_cipher_negotiation.png`<br>`evidence/video_demonstration/video_09_display_filter_server_hello_type2.png` |
| **11** | **Server Name Indication (SNI)** | `tls.handshake.extensions_server_name` | Hostname observed: **`mobile.events.data.microsoft.com`** | Not present in video capture slice | The SNI extension communicates the target domain name in cleartext during Client Hello prior to encryption. Identifies destination cloud telemetry endpoint. | `evidence/12_client_hello_detailed_parameters.png` |
| **12** | **TLS Application Data** | `tls.app_data` / `ip.addr == 40.79.141.157` | **21 packets matched** target endpoint (Frames 12, 15, 16, 18, 22, 25 are app data) | **0 packets matched** with filter `tls.app_data` (records classified as Encrypted Records) | Application data is encrypted using AEAD symmetric session keys (`AES-256-GCM`). Payloads cannot be deciphered without session secrets. | `evidence/11_filter_endpoint_all_packets.png`<br>`evidence/video_demonstration/video_10_display_filter_tls_app_data.png` |
| **13** | **TCP Retransmission** | `tcp.analysis.retransmission` | **0 matching packets** for endpoint `40.79.141.157` | **0 matching packets** for filter `tcp.analysis.retransmission` (video showed Fast Retransmissions) | The filter `tcp.analysis.retransmission` specifically matches standard retransmissions. In the separate college video capture, Wireshark flagged packets 1788, 1885, 1920 under `[TCP Fast Retransmission]`. | `evidence/14_filter_tcp_retransmission_check.png`<br>`evidence/video_demonstration/video_11_display_filter_tcp_retransmission_check.png` |
| **14** | **Duplicate ACK** | `tcp.analysis.duplicate_ack` | **0 matching packets** | **0 matching packets** | No duplicate ACK packets were identified in either dataset, indicating no significant out-of-order segment arrivals or ACK loss. | `evidence/15_filter_tcp_duplicate_ack_check.png`<br>`evidence/video_demonstration/video_12_display_filter_tcp_duplicate_ack_check.png` |
| **15** | **TCP FIN** | `tcp.flags.fin == 1` | **0 matching packets** | **0 matching packets** | No graceful TCP FIN connection teardown packets were observed. Indicates sessions were maintained via keep-alive or remained open when capture ended. | `evidence/16_filter_tcp_fin_check.png`<br>`evidence/video_demonstration/video_13_display_filter_tcp_fin_check.png` |
| **16** | **TCP Reset (RST)** | `tcp.flags.reset == 1` | **0 matching packets** | **0 matching packets** | No TCP RST packets were observed. Confirms no abrupt connection termination, port rejections, or active firewall resets occurred. | `evidence/17_filter_tcp_reset_check.png`<br>`evidence/video_demonstration/video_14_display_filter_tcp_reset_check.png` |

---

### 5. Security Findings

1. **Predominance of Encrypted Protocols:**  
   Across both captures, all web and application communications utilized TCP port 443 with TLS protection (TLS 1.2 and TLS 1.3). No cleartext HTTP sessions were detected (`http` = 0 packets).
2. **Absence of Plaintext DNS Over UDP Port 53:**  
   Conventional DNS queries were absent (`dns` = 0 packets). Name resolution requests were either fulfilled by local operating system resolver caches or encrypted via DNS-over-HTTPS (DoH).
3. **Cryptographic Posture & Cipher Strength:**  
   In the home baseline capture (`40.79.141.157`), the connection negotiated modern **TLS 1.3** utilizing cipher suite **`TLS_AES_256_GCM_SHA384` (0x1302)**, elliptic curve key exchange on **`secp384r1`**, and disabled compression (`null (0)`), eliminating vulnerability to CRIME/BREACH side-channel attacks.
4. **Endpoint Telemetry Identification via SNI:**  
   Server Name Indication inspection of Frame 6 revealed the destination host **`mobile.events.data.microsoft.com`**, representing standard Microsoft Windows operating system telemetry and cloud diagnostics.
5. **Payload Confidentiality via Stream Reassembly:**  
   Reconstruction of TCP Stream 0 (`Follow TCP Stream`) confirmed 13 KB of high-entropy binary ciphertext with zero leakage of plaintext authentication tokens, headers, or cookies.
6. **Network Reliability & Retransmission Discrepancy:**  
   - In the home baseline capture, zero retransmissions, zero duplicate ACKs, zero FINs, and zero RSTs were recorded.
   - In the earlier college capture demonstrated in the video, Wireshark flagged packets 1788, 1885, 1920, 3128, and 3289 as `[TCP Fast Retransmission]`. These events belong strictly to the college network dataset and should not be confused with or merged into the home capture.

---

### 6. Security Recommendations

1. **Enforce Strict Egress Filtering (Zero Trust Perimeter):**  
   Restrict outbound workstation egress traffic to necessary enterprise ports (`80`, `443`, `53`, `853`). Block direct outbound connections to sensitive database ports such as Redis (`6379`) or MySQL (`3306`).
2. **Mandate TLS 1.3 & Disable Insecure Ciphers:**  
   Enforce TLS 1.3 across all endpoints. Ensure deprecated legacy protocols (SSLv3, TLS 1.0, TLS 1.1) and obsolete ciphers (RC4, 3DES, CBC mode) remain permanently disabled.
3. **Disable Unnecessary Local Discovery Protocols:**  
   Disable SSDP (UPnP) on port 1900 and mDNS on port 5353 on corporate workstations to prevent local network reconnaissance, host fingerprinting, and broadcast amplification.
4. **Deploy Deep Packet Inspection (DPI) & SNI Auditing:**  
   Implement Next-Generation Firewall (NGFW) policies inspecting SNI fields to detect unauthorized data exfiltration or connections to unsanctioned external domains.
5. **Implement IDS/IPS Alert Signatures:**  
   Deploy network intrusion detection rules (e.g., Snort/Suricata) to alert on unexpected non-standard egress:
   ```snort
   alert tcp $HOME_NET any -> $EXTERNAL_NET 6379 (msg:"SECURITY ALERT: Direct Outbound Redis Connection Attempt"; flow:to_server; sid:1000001; rev:1;)
   ```

---

### 7. Limitations

1. **Sample Scope:** The findings are strictly constrained to the frames captured during the recording windows and the specific display filters evaluated.
2. **Zero-Result Filter Interpretation:** Display filters yielding zero packets (e.g., `http`, `dns`, `tcp.flags.reset == 1`) confirm that no matching packets exist in the captured file; they do not prove that such events never occurred outside the capture timeframe or on other network interfaces.
3. **Dataset Separation:** The observations of 94.8% IPv6, 71.3% TLS bytes, 12 TCP conversations, and 21 TLS Application Data packets originate from the Home Baseline Capture (`wireshark_Wi-FiFH69W3.pcapng` & `wireshark_Wi-FiPOLDX3.pcapng`). The Fast Retransmission observations originate from the College Video Capture (`wireshark_Wi-FiCIHYX3.pcapng`). The two captures represent distinct operating environments and are documented as separate datasets.

---

### 8. Conclusion

This practical provided hands-on experience in defensive packet analysis, protocol hierarchy profiling, TCP state machine evaluation, and TLS cryptographic dissection using Wireshark. 

The investigation confirmed that all active web sessions were secured through modern TLS encryption, successfully eliminating vulnerabilities associated with plaintext HTTP and unauthenticated transmission. Crucially, the exercise reinforced the necessity of disciplined analytical rigor—drawing conclusions strictly supported by packet evidence and properly differentiating results between independent network captures.

---

### Appendix: Wireshark Display Filters Reference

```wireshark
# Network Layer Filters
ipv6
ip.addr == 40.79.141.157

# Transport Layer Filters
tcp
tcp.port == 443
tcp.flags.syn == 1 && tcp.flags.ack == 0
tcp.flags.fin == 1
tcp.flags.reset == 1
tcp.analysis.retransmission
tcp.analysis.duplicate_ack

# Application & Security Protocol Filters
http
http.request
dns
tls
tls.handshake
tls.handshake.type == 1
tls.handshake.type == 2
tls.handshake.extensions_server_name
tls.handshake.extensions_server_name == "mobile.events.data.microsoft.com"
tls.app_data
```

---
*Report submitted by **Ziyakausar J. Tamboli** (Intern ID: `SWX-2026-002678`) in fulfillment of Task 2: Network Security Analysis for the Cyber Security Internship at **SWYNEX Technologies**.*
