# 🛡️ SWYNEX-Network-Security-Analysis
### Cyber Security Internship — Task 2: Network Security Analysis Using Wireshark
**Organization:** [SWYNEX Technologies](https://swynex.com)  
**Intern Name:** Ziyakausar Tamboli  
**Intern ID:** `SWX-2026-002678`  
**Domain:** Cyber Security  
**Submission Repository:** [SWYNEX-Network-Security-Analysis](https://github.com/ziyakausar07/SWYNEX-Network-Security-Analysis)  

---

![Wireshark](https://img.shields.io/badge/Wireshark-4.x-1679A7?style=for-the-badge&logo=wireshark&logoColor=white)
![Security](https://img.shields.io/badge/Domain-Cyber%20Security-red?style=for-the-badge&logo=security)
![Protocol](https://img.shields.io/badge/Protocols-TCP%20%7C%20IPv6%20%7C%20TLSv1.3-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Task%20Status-Complete%20%26%20Verified-success?style=for-the-badge)

---

## 📌 1. Project Overview

This project was conducted as part of the **Cyber Security Internship at SWYNEX Technologies (Task 2)**. The objective of this task is to perform an end-to-end defensive network traffic analysis using **Wireshark** in a controlled workstation environment.

The investigation inspects network communications across all major OSI layers, profiles protocol distribution, audits TCP three-way handshakes and state machines, evaluates Transport Layer Security (TLS 1.2/1.3) cryptographic negotiations, verifies Server Name Indication (SNI) records, tests defensive Wireshark display filters, and outlines defensive hardening strategies.

---

## 📋 2. Comprehensive Analysis Checklist (11/11 Verified)

All eleven core analytical criteria specified in the assessment have been systematically executed and verified:

| No. | Analysis Category | Wireshark Display Filter / Tool | Status | Primary Finding |
|:---:|:---|:---|:---:|:---|
| **1** | **Protocol hierarchy** | Protocol Hierarchy Statistics | ✅ | IPv6 prominent (94.8%); TLS constitutes 71.3% of total byte volume. |
| **2** | **TCP conversations** | Conversations Matrix (TCP Tab) | ✅ | 12 active streams; high-range ephemeral ports connecting to port 443 (HTTPS). |
| **3** | **HTTP filter** | `http` | ✅ | 0 packets matched; absence of legacy unencrypted plaintext web communication. |
| **4** | **DNS filter** | `dns` | ✅ | 0 packets on UDP port 53; indicates utilization of DoH or local OS caching. |
| **5** | **TLS handshake** | `tls.handshake` | ✅ | 2 matching packets (Packet 6 & 7) representing Client Hello and Server Hello. |
| **6** | **Client Hello & Server Hello** | Packet Tree Dissection | ✅ | SNI `mobile.events.data.microsoft.com`; negotiated cipher `TLS_AES_256_GCM_SHA384`. |
| **7** | **TLS Application Data** | `ip.addr == 40.79.141.157` | ✅ | 21 packets matched; full lifecycle from 3-way handshake to encrypted records. |
| **8** | **TCP retransmission** | `ip.addr == 40.79.141.157 && tcp.analysis.retransmission` | ✅ | 0 packets matched; no packet loss or network degradation observed for endpoint. |
| **9** | **Duplicate ACK** | `ip.addr == 40.79.141.157 && tcp.analysis.duplicate_ack` | ✅ | 0 packets matched; no out-of-order segment acknowledgments detected. |
| **10** | **TCP FIN** | `ip.addr == 40.79.141.157 && tcp.flags.fin == 1` | ✅ | 0 packets matched; no standard TCP teardown observed within capture window. |
| **11** | **TCP RST** | `ip.addr == 40.79.141.157 && tcp.flags.reset == 1` | ✅ | 0 packets matched; no connection resets or abnormal terminations observed. |

---

## 📊 3. Protocol Hierarchy & Distribution Analysis (Point 1)

In the primary baseline capture (`wireshark_Wi-FiFH69W3.pcapng`), **134 packets** comprising **33,935 bytes** were captured and analyzed.

<div align="center">
  <img src="evidence/02_protocol_hierarchy_statistics.png" alt="Wireshark Protocol Hierarchy" width="850px" />
  <p><em>Figure 1: Wireshark Protocol Hierarchy Statistics Breakdown</em></p>
</div>

| Protocol Layer | Packets | % Packets | Bytes | % Bytes | Role & Description |
|:---|:---:|:---:|:---:|:---:|:---|
| **Ethernet** | 134 | 100.0% | 33,935 B | 100.0% | Layer 2 framing |
| **IPv6 (Internet Protocol v6)** | 127 | 94.8% | 5,080 B | 15.0% | Modern routable network layer |
| ├── **TCP (Transmission Control)** | 117 | 87.3% | 2,568 B | 7.6% | Reliable transport layer |
| │   └── **TLS (Transport Layer Security)** | 49 | 36.6% | 24,184 B | **71.3%** | Encrypted application traffic |
| ├── **UDP (User Datagram)** | 9 | 6.7% | 72 B | 0.2% | Connectionless transport |
| │   └── **mDNS (Multicast DNS)** | 1 | 0.7% | 465 B | 1.4% | Local link-local name resolution |
| └── **ICMPv6** | 1 | 0.7% | 88 B | 0.3% | Router Advertisement control packet |
| **IPv4 (Internet Protocol v4)** | 7 | 5.2% | 148 B | 0.4% | Legacy network layer |
| ├── **SSDP (Simple Service Discovery)** | 1 | 0.7% | 379 B | 1.1% | UPnP device discovery broadcast |
| ├── **mDNS** | 1 | 0.7% | 465 B | 1.4% | Multicast DNS over IPv4 |
| └── **IGMP** | 2 | 1.5% | 36 B | 0.1% | Multicast group membership |

---

## 🌐 4. Endpoint & Conversation Analysis (Point 2)

Auditing Wireshark conversation matrices reveals communicating nodes across Layers 2, 3, and 4:

### 4.1 Layer 2 & Layer 3 Conversations
<div align="center">
  <img src="evidence/03_conversations_ethernet_layer2.png" alt="Layer 2 Ethernet Conversations" width="850px" />
  <p><em>Figure 2: Layer 2 Ethernet MAC Conversations</em></p>
</div>

<div align="center">
  <img src="evidence/04_conversations_ipv4.png" alt="IPv4 Conversations" width="850px" />
  <p><em>Figure 3: Layer 3 IPv4 Conversations Matrix</em></p>
</div>

<div align="center">
  <img src="evidence/05_conversations_ipv6.png" alt="IPv6 Conversations" width="850px" />
  <p><em>Figure 4: Layer 3 IPv6 Conversations Matrix</em></p>
</div>

### 4.2 Layer 4 TCP & UDP Conversations
<div align="center">
  <img src="evidence/06_conversations_tcp_sessions.png" alt="TCP Sessions" width="850px" />
  <p><em>Figure 5: Layer 4 TCP Stream Sessions (12 Active Streams to Port 443)</em></p>
</div>

<div align="center">
  <img src="evidence/07_conversations_udp_traffic.png" alt="UDP Sessions" width="850px" />
  <p><em>Figure 6: Layer 4 UDP Conversations (SSDP, mDNS, QUIC)</em></p>
</div>

---

## 🔍 5. TCP Three-Way Handshake & Flag Analysis

Applying the filter `tcp.flags.syn == 1 && tcp.flags.ack == 0` isolates TCP connection requests:

<div align="center">
  <img src="evidence/08_filter_tcp_syn_flag.png" alt="TCP SYN Filter" width="850px" />
  <p><em>Figure 7: Display Filter Isolating TCP SYN Packet</em></p>
</div>

<div align="center">
  <img src="evidence/09_tcp_syn_packet_details.png" alt="TCP SYN Packet Dissection" width="850px" />
  <p><em>Figure 8: Packet Details Window for TCP SYN (Packet #3)</em></p>
</div>

- **Source / Destination:** `192.168.29.161:53790 -> 40.79.141.157:443`
- **TCP Flags:** `0x002 (SYN)` | Initial Sequence Number (raw): `2676126983`.
- **Window Size:** `65535` bytes | **Window Scale (WS):** `256` multiplier.
- **Maximum Segment Size (MSS):** `1460` bytes | **SACK Permitted:** `1`.

---

## 📡 6. Endpoint Traffic & TLS Application Data Analysis (Point 7)

Applying the filter `ip.addr == 40.79.141.157` isolates all communication with the remote cloud endpoint:

<div align="center">
  <img src="evidence/11_filter_endpoint_all_packets.png" alt="Endpoint Traffic Filter" width="850px" />
  <p><em>Figure 9: Filter ip.addr == 40.79.141.157 (21 Packets Displayed: SYN, SYN-ACK, ACK, Handshakes, and TLS Application Data)</em></p>
</div>

- **Handshake Flow:** Packet 3 (`SYN`), Packet 4 (`SYN, ACK`), Packet 5 (`ACK`) confirm successful TCP connection setup.
- **TLS Handshake:** Packet 6 (`Client Hello`) and Packet 7 (`Server Hello, Change Cipher Spec`).
- **Application Data Exchange:** Packets 12, 15, 16, 18, 22, and 25 convey encrypted **TLS Application Data** records protected by symmetric AEAD encryption.

---

## 🔐 7. Cryptographic Handshake Deep Dissection (Points 5 & 6)

Applying the filter `tls.handshake` isolates the cryptographic negotiation phase between client and server:

<div align="center">
  <img src="evidence/10_filter_tls_handshake_sni.png" alt="TLS Filter Overview" width="850px" />
  <p><em>Figure 10: Display Filter tls Showing Active Encrypted Sessions</em></p>
</div>

### 7.1 Client Hello Analysis (Packet 6)
<div align="center">
  <img src="evidence/12_client_hello_detailed_parameters.png" alt="Client Hello Parameters" width="850px" />
  <p><em>Figure 11: Packet 6 Detailed Dissection — Client Hello (SNI: mobile.events.data.microsoft.com, 20 Cipher Suites, Key Shares)</em></p>
</div>

- **Server Name Indication (SNI):** Identifies target hostname **`mobile.events.data.microsoft.com`**.
- **Supported Versions:** Offered `TLS 1.3` and `TLS 1.2`.
- **Cipher Suites Offered:** **20 modern cipher suites** offered by client.
- **Supported Groups / Key Shares:** `x25519`, `secp256r1`, and `secp384r1`.

### 7.2 Server Hello Analysis (Packet 7)
<div align="center">
  <img src="evidence/13_server_hello_cipher_negotiation.png" alt="Server Hello Negotiation" width="850px" />
  <p><em>Figure 12: Packet 7 Detailed Dissection — Server Hello (Negotiated TLS 1.3, TLS_AES_256_GCM_SHA384, null Compression)</em></p>
</div>

- **Negotiated Protocol Version:** `supported_versions` extension negotiated **TLS 1.3**.
- **Selected Cipher Suite:** **`TLS_AES_256_GCM_SHA384` (0x1302)** — authenticated encryption using 256-bit AES in GCM mode.
- **Compression Method:** **`null (0)`** (Compression disabled, preventing CRIME/BREACH side-channel attacks).
- **Key-Share Agreement:** Server selected elliptic curve **`secp384r1`**.

---

## ⚡ 8. TCP Anomaly & Lifecycle Verification (Points 8, 9, 10, 11)

Targeted defensive filters were evaluated against the endpoint session (`40.79.141.157`):

### 8.1 TCP Retransmission Check (Point 8)
<div align="center">
  <img src="evidence/14_filter_tcp_retransmission_check.png" alt="TCP Retransmission Check" width="850px" />
  <p><em>Figure 13: Filter ip.addr == 40.79.141.157 && tcp.analysis.retransmission (0 Packets Matching)</em></p>
</div>
- **Result:** 0 matching packets. Confirms zero segment loss or throughput starvation for this session.

### 8.2 TCP Duplicate ACK Check (Point 9)
<div align="center">
  <img src="evidence/15_filter_tcp_duplicate_ack_check.png" alt="TCP Duplicate ACK Check" width="850px" />
  <p><em>Figure 14: Filter ip.addr == 40.79.141.157 && tcp.analysis.duplicate_ack (0 Packets Matching)</em></p>
</div>
- **Result:** 0 matching packets. Confirms no out-of-order delivery or network congestion.

### 8.3 TCP FIN Teardown Check (Point 10)
<div align="center">
  <img src="evidence/16_filter_tcp_fin_check.png" alt="TCP FIN Check" width="850px" />
  <p><em>Figure 15: Filter ip.addr == 40.79.141.157 && tcp.flags.fin == 1 (0 Packets Matching)</em></p>
</div>
- **Result:** 0 matching packets. The connection maintained active session state throughout the capture window.

### 8.4 TCP Reset (RST) Check (Point 11)
<div align="center">
  <img src="evidence/17_filter_tcp_reset_check.png" alt="TCP Reset Check" width="850px" />
  <p><em>Figure 16: Filter ip.addr == 40.79.141.157 && tcp.flags.reset == 1 (0 Packets Matching)</em></p>
</div>
- **Result:** 0 matching packets. Confirms no abnormal connection drops or port rejection anomalies.

---

## 🔒 9. Application Payload Confidentiality Audit

Using Wireshark **Follow TCP Stream (tcp.stream eq 0)** on the communication to `40.79.141.157:443`:

<div align="center">
  <img src="evidence/18_follow_tcp_stream_encrypted_payload.png" alt="Follow TCP Stream" width="850px" />
  <p><em>Figure 17: Follow TCP Stream (Stream 0) Confirming High-Entropy Encrypted Ciphertext</em></p>
</div>

- **Inspection Outcome:** The stream contains 13 KB of high-entropy binary ciphertext.
- **Defensive Significance:** Confirms complete application-layer confidentiality. No plaintext credentials, HTTP headers, authentication cookies, or tokens are exposed to passive eavesdroppers.

---

## 🚨 10. Investigation of Historical Port 6379 (Redis Context)

During preliminary baseline observation, an outbound connection was noted: `10.204.128.120:57716 -> 13.204.54.36:6379` (196 packets, ~16 KB).

- **Threat Vector:** TCP port `6379` is assigned to Redis. Unauthenticated Redis instances exposed to public networks are vulnerable to remote code execution (RCE) and database exfiltration.
- **Verification Result:** Port 6379 traffic was **absent** from the finalized capture files (`wireshark_Wi-FiFH69W3` and `wireshark_Wi-FiPOLDX3`).
- **Defensive Precaution:** Workstation firewalls must enforce strict egress controls preventing direct access to non-standard database ports across public Internet perimeters.

---

## 🛡️ 11. Defensive Recommendations & Countermeasures

1. **Zero Trust Outbound Egress Filtering:** Restrict outbound workstation traffic to authorized enterprise ports (`80`, `443`, `53`, `853`), blocking direct access to database ports like Redis `6379` or MySQL `3306`.
2. **Disable Unnecessary Local Discovery Services:** Turn off SSDP / UPnP discovery and mDNS on enterprise workstations to minimize local network fingerprinting.
3. **Mandate Modern Cryptography (TLS 1.3):** Enforce TLS 1.3 with forward secrecy (`TLS_AES_256_GCM_SHA384`), deprecating TLS 1.0, 1.1, and legacy ciphers (3DES, RC4).
4. **Deep Packet Inspection (DPI) & SNI Filtering:** Implement Next-Generation Firewall (NGFW) policies evaluating Server Name Indication (SNI) records to detect rogue domains or unauthorized data transfers.
5. **Intrusion Detection System (IDS) Alerting:** Deploy Suricata / Snort alert signatures:
   ```snort
   alert tcp $HOME_NET any -> $EXTERNAL_NET 6379 (msg:"WARN: Direct External Redis Traffic Attempted"; sid:1000001; rev:1;)
   ```

---

## 📁 12. Project Repository Structure

```text
SWYNEX-Network-Security-Analysis/
├── evidence/
│   ├── 01_main_packet_capture_overview.png
│   ├── 02_protocol_hierarchy_statistics.png
│   ├── 03_conversations_ethernet_layer2.png
│   ├── 04_conversations_ipv4.png
│   ├── 05_conversations_ipv6.png
│   ├── 06_conversations_tcp_sessions.png
│   ├── 07_conversations_udp_traffic.png
│   ├── 08_filter_tcp_syn_flag.png
│   ├── 09_tcp_syn_packet_details.png
│   ├── 10_filter_tls_handshake_sni.png
│   ├── 11_filter_endpoint_all_packets.png
│   ├── 12_client_hello_detailed_parameters.png
│   ├── 13_server_hello_cipher_negotiation.png
│   ├── 14_filter_tcp_retransmission_check.png
│   ├── 15_filter_tcp_duplicate_ack_check.png
│   ├── 16_filter_tcp_fin_check.png
│   ├── 17_filter_tcp_reset_check.png
│   └── 18_follow_tcp_stream_encrypted_payload.png
├── report/
│   └── Network_Security_Analysis_Report.md
└── README.md
```

---

## 🎓 13. Conclusion

Completing Task 2 of the **SWYNEX Technologies Cyber Security Internship** provided hands-on experience in defensive packet-level auditing. By combining macro-level protocol hierarchy analysis with micro-level TCP and TLS flag dissections, this project verified that all 11 assessment criteria are satisfied, ensuring robust data confidentiality through modern TLS 1.3 encryption and establishing comprehensive defensive controls for network security.

---
*Authored by **Ziyakausar Tamboli** | Intern ID: `SWX-2026-002678` | Cyber Security Intern @ SWYNEX Technologies*
