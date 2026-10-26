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
![Status](https://img.shields.io/badge/Task%20Status-Ready%20for%20Review-success?style=for-the-badge)

---

## 📌 1. Project Overview

This project was conducted as part of the **Cyber Security Internship at SWYNEX Technologies (Task 2)**. The objective of this task is to perform an end-to-end defensive network traffic analysis using **Wireshark** in a controlled workstation environment. 

The investigation inspects network communications across all major OSI layers, profiles the protocol hierarchy, verifies TCP three-way handshakes and state machines, evaluates Transport Layer Security (TLS 1.2/1.3) cryptographic handshakes and Server Name Indication (SNI) records, tests defensive Wireshark display filters, and provides structured defensive recommendations to harden network infrastructure.

---

## 🎯 2. Objectives & Scope

1. **Traffic Ingestion & Inspection:** Capture and parse live network packets across Wi-Fi interfaces.
2. **Protocol Breakdown:** Quantify protocol percentages and byte volume distribution using the Protocol Hierarchy Statistics tool.
3. **Endpoint & Session Mapping:** Audit communicating endpoints across Ethernet (L2), IPv4/IPv6 (L3), and TCP/UDP (L4).
4. **TCP Handshake & State Analysis:** Dissect TCP flag structures (`SYN`, `ACK`, `RST`), sequence numbers, window sizing, and retransmission behaviors.
5. **TLS & Cryptographic Verification:** Inspect TLS Client/Server Hello handshakes, extract SNI hostnames, and evaluate cipher negotiations.
6. **Application Stream Reassembly:** Inspect bidirectional TCP streams to verify data confidentiality and ensure sensitive cleartext is not exposed on the wire.
7. **Defensive Hardening Strategy:** Formulate actionable, vendor-neutral security recommendations and preventive countermeasures.

---

## 🔬 3. Analytical Environment & Tools

| Component | Technical Details |
|:---|:---|
| **Operating System** | Windows 11 Enterprise / Home |
| **Analysis Platform** | Wireshark Protocol Analyzer (v4.x) |
| **Capture Interface** | 802.11 Wi-Fi Wireless Interface (`\Device\NPF_{FD74D2C3-...}`) |
| **Capture Profiles** | `wireshark_Wi-FiFH69W3.pcapng` (134 frames) & `wireshark_Wi-FiPOLDX3.pcapng` (122 frames) |
| **Dissection Modules** | Protocol Hierarchy, Conversation Matrix, Follow TCP Stream, Display Filter Engine |

---

## 📊 4. Protocol Hierarchy & Distribution Analysis

In the primary baseline capture (`wireshark_Wi-FiFH69W3.pcapng`), **134 packets** comprising **33,935 bytes** were captured and analyzed.

<div align="center">
  <img src="evidence/02_protocol_hierarchy_statistics.png" alt="Wireshark Protocol Hierarchy" width="850px" />
  <p><em>Figure 1: Wireshark Protocol Hierarchy Statistics Breakdown</em></p>
</div>

### Protocol Distribution Summary Table

| Protocol Name | Packets | % Packets | Bytes | % Bytes | Role & Description |
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

> **Key Finding:** IPv6 accounts for **94.8%** of packets, reflecting modern dual-stack ISP routing. Crucially, **TLS encapsulates 71.3% of the total network bytes**, proving that the overwhelming majority of application payloads are cryptographically protected.

---

## 🌐 5. Endpoint & Conversation Analysis

Auditing Wireshark conversation matrices reveals how endpoints interact across network layers:

### 5.1 Layer 2 — Ethernet Conversations
<div align="center">
  <img src="evidence/03_conversations_ethernet_layer2.png" alt="Layer 2 Ethernet Conversations" width="850px" />
  <p><em>Figure 2: Layer 2 Ethernet MAC Conversations</em></p>
</div>

- **Local Workstation NIC:** `f8:54:f6:b3:36:4d` (AzureWave Technology).
- **Default Gateway / Wireless Router:** `20:89:8a:af:c6:91` (Skyworth Digital Technology).
- **Unicast Traffic:** 94 frames (20 KB) exchanged between workstation and gateway.
- **Multicast Discovery:** Broadcasts dispatched to `01:00:5e:00:00:01` (IPv4 all systems) and `33:33:00:00:00:01` (IPv6 all nodes).

### 5.2 Layer 3 — IPv4 & IPv6 Conversations
<div align="center">
  <img src="evidence/04_conversations_ipv4.png" alt="IPv4 Conversations" width="850px" />
  <p><em>Figure 3: Layer 3 IPv4 Conversations Matrix</em></p>
</div>

<div align="center">
  <img src="evidence/05_conversations_ipv6.png" alt="IPv6 Conversations" width="850px" />
  <p><em>Figure 4: Layer 3 IPv6 Conversations Matrix</em></p>
</div>

- **IPv4 Endpoints:** Local host `192.168.29.161` interacting with Microsoft Azure cloud IP `40.79.141.157`, along with subnet broadcasts (`192.168.29.255`, `224.0.0.251`, `239.255.255.250`).
- **IPv6 Endpoints:** Host `2405:201:d043:...` communicated with:
  - `2606:4700:9c68:69e:62c6:d7:3250:27c5` (Cloudflare CDN Anycast Node): **105 packets, 30 KB**.
  - `2001:4860:4840:400::` / `2001:4860:4846:400::` (Google Edge Services): 4 packets.
  - `2603:1040:a06:6::1` (Microsoft Cloud Services): 5 packets.

### 5.3 Layer 4 — TCP & UDP Transport Sessions
<div align="center">
  <img src="evidence/06_conversations_tcp_sessions.png" alt="TCP Sessions" width="850px" />
  <p><em>Figure 5: Layer 4 TCP Stream Sessions</em></p>
</div>

<div align="center">
  <img src="evidence/07_conversations_udp_traffic.png" alt="UDP Sessions" width="850px" />
  <p><em>Figure 6: Layer 4 UDP Conversations</em></p>
</div>

- **TCP:** 12 active streams, all directed to destination port **443 (HTTPS)** with dynamic ephemeral client ports (`50106`–`50115`, `53790`, `62203`).
- **UDP:** 6 streams representing SSDP discovery (port 1900), mDNS (port 5353), and HTTP/3 QUIC sessions (port 443).

---

## 🔍 6. In-Depth TCP Handshake & State Machine Inspection

Applying the filter `tcp.flags.syn == 1 && tcp.flags.ack == 0` isolates TCP connection requests:

<div align="center">
  <img src="evidence/08_filter_tcp_syn_flag.png" alt="TCP SYN Filter" width="850px" />
  <p><em>Figure 7: Display Filter Isolating TCP SYN Packet</em></p>
</div>

<div align="center">
  <img src="evidence/09_tcp_syn_packet_details.png" alt="TCP SYN Packet Dissection" width="850px" />
  <p><em>Figure 8: Packet Details Window for TCP SYN (Packet #3)</em></p>
</div>

### Detailed Dissection of Packet #3
- **Source:** `192.168.29.161:53790` | **Destination:** `40.79.141.157:443`
- **TCP Flags:** `0x002 (SYN)`
- **Sequence Number:** `0` (Relative) | `2676126983` (Raw Initial Sequence Number).
- **Advertised Window Size:** `65535` bytes.
- **Window Scaling (WS):** `256` multiplier (8-bit shift) for high-bandwidth utilization.
- **Maximum Segment Size (MSS):** `1460` bytes (Ethernet MTU 1500 - 40 bytes IP/TCP header).
- **Selective Acknowledgment (SACK):** `SACK_PERM=1` enabled, allowing resilient packet recovery during congestion.

---

## 🔐 7. Cryptographic & TLS Protocol Analysis

Executing the `tls` display filter displays active cryptographic handshakes and application data frames:

<div align="center">
  <img src="evidence/10_filter_tls_handshake_sni.png" alt="TLS Filter and Handshake" width="850px" />
  <p><em>Figure 9: TLS Display Filter Revealing Client Hello & SNI Extension</em></p>
</div>

### Key TLS Handshake Highlights:
1. **Frame 6 — Client Hello:**
   - Client announces TLS 1.3 capabilities.
   - **Server Name Indication (SNI):** Extracted hostname confirms **`mobile.events.data.microsoft.com`** (Microsoft Telemetry & Cloud diagnostics).
2. **Frame 7 — Server Hello & Change Cipher Spec:**
   - Microsoft server selects preferred high-security cipher suite (`TLS_AES_128_GCM_SHA256`).
3. **Application Data Frames (Frames 12, 15, 16, 18, 22, 25):**
   - Cryptographically protected bidirectional transmission.
4. **Additional SNI Observed (`wireshark_Wi-FiFH69W3.pcapng` Frame 4):**
   - Client Hello identified **`api1.reasonsecurity.com`** (ReasonLabs / RAV Antivirus endpoint protection telemetry).

### Payload Inspection via "Follow TCP Stream"
<div align="center">
  <img src="evidence/11_follow_tcp_stream_encrypted_payload.png" alt="Follow TCP Stream" width="850px" />
  <p><em>Figure 10: Follow TCP Stream Window (Stream 0) Demonstrating High-Entropy Encrypted Payload</em></p>
</div>

- **Inspection Outcome:** The stream contains 13 KB of high-entropy binary ciphertext.
- **Defensive Significance:** Confirms complete application-layer confidentiality. No plaintext credentials, HTTP headers, authentication cookies, or tokens are exposed to passive eavesdroppers.

---

## 🚨 8. Investigation of Port 6379 (Redis Observation)

In an earlier monitoring test, an outbound connection was recorded to port `6379` (`10.204.128.120:57716 -> 13.204.54.36:6379`, 196 packets, ~16 KB).

- **Port Context:** TCP port `6379` is assigned to **Redis** (in-memory data store).
- **Threat Vector:** Unauthenticated Redis instances exposed to public networks are vulnerable to unauthorized key reading, rogue database wiping (`FLUSHALL`), and remote code execution (RCE) via rogue module injection or SSH key overwrites.
- **Verification Result:** Port 6379 traffic was **absent** from the finalized capture files (`wireshark_Wi-FiFH69W3` and `wireshark_Wi-FiPOLDX3`).
- **Defensive Precaution:** Workstation firewalls must enforce strict egress controls preventing direct access to non-standard database ports across public Internet perimeters.

---

## 🧪 9. Wireshark Display Filter Testing Matrix

| No. | Display Filter Syntax | Packets Returned | Analytical Interpretation & Security Implication |
|:---:|:---|:---:|:---|
| 1 | `tcp.analysis.retransmission` | 1 packet (Profile A)<br>0 (Profile B) | Measures segment loss; single retransmission reflects wireless jitter, not network DoS. |
| 2 | `tcp.analysis.duplicate_ack` | 1 packet (Profile A)<br>0 (Profile B) | Receiver requesting dropped segment; normal TCP fast-recovery behavior. |
| 3 | `tcp.flags.syn == 1 && tcp.flags.ack == 0` | 1 packet (Profile B) | Successfully isolates initial TCP connection handshake request (`53790 -> 443`). |
| 4 | `http` | 0 packets | Verifies absence of unencrypted legacy plaintext HTTP traffic. |
| 5 | `dns` | 0 packets (port 53) | Standard unencrypted UDP 53 DNS absent; DNS-over-HTTPS or OS cache utilized. |
| 6 | `tls` | 30 packets (Profile B)<br>49 packets (Profile A) | Verifies encrypted TLS 1.2/1.3 communication across all external sessions. |
| 7 | `tls.handshake` | 2 packets (Profile B) | Validates Client Hello and Server Hello negotiation. |
| 8 | `tcp.flags.reset == 1` | 1 packet (Profile A) | Orderly socket termination (`RST, ACK`) initiated by endpoint. |

---

## 🛡️ 10. Defensive Recommendations & Countermeasures

1. **Zero Trust Outbound Egress Filtering:**
   - Restrict outbound workstation traffic to authorized enterprise ports (`80`, `443`, `53`, `853`).
   - Block direct egress attempts to backend database ports (e.g., Redis `6379`, MySQL `3306`, PostgreSQL `5432`) at edge firewalls.
2. **Disable Unnecessary Local Discovery Services:**
   - Turn off SSDP / UPnP discovery and mDNS on enterprise workstations where service advertising is unnecessary to minimize host fingerprinting.
3. **Enforce Modern Cryptography (TLS 1.3):**
   - Mandate TLS 1.3 and forward-secrecy cipher suites (`TLS_AES_128_GCM_SHA256`, `ECDHE-RSA-AES128-GCM-SHA256`).
   - Deprecate TLS 1.0, 1.1, and legacy ciphers (3DES, RC4).
4. **Implement Deep Packet Inspection (DPI) & SNI Filtering:**
   - Use Next-Generation Firewalls (NGFW) to inspect Server Name Indication (SNI) extensions for communication with newly observed or categorized malicious domains.
5. **Intrusion Detection System (IDS) Alerting:**
   - Deploy Suricata / Snort signatures to detect rogue database connection attempts:
   ```snort
   alert tcp $HOME_NET any -> $EXTERNAL_NET 6379 (msg:"WARN: Direct External Redis Traffic Attempted"; sid:1000001; rev:1;)
   ```
6. **Data Sanitization for Diagnostic Captures:**
   - Ensure all `.pcapng` packet captures are scrubbed of internal IP topology, MAC addresses, and credentials prior to sharing.

---

## 📁 11. Project Repository Structure

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
│   └── 11_follow_tcp_stream_encrypted_payload.png
├── report/
│   └── Network_Security_Analysis_Report.md
└── README.md
```

---

## 🎓 12. Conclusion & Reflection

Completing Task 2 of the **SWYNEX Technologies Cyber Security Internship** provided hands-on experience in defensive packet-level auditing. By combining macro-level protocol hierarchy analysis with micro-level TCP and TLS flag dissections, this project verified that the inspected environment maintains robust data confidentiality through modern TLS encryption, while outlining the preventative controls necessary to safeguard enterprise networks against unauthorized exposure.

---
*Authored by **Ziyakausar Tamboli** | Intern ID: `SWX-2026-002678` | Cyber Security Intern @ SWYNEX Technologies*
