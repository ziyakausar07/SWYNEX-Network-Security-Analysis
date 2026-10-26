# 📱 LinkedIn Explanation Post — Ready to Copy & Publish

> **Instructions for Ziyakausar:**
> 1. Copy the text below into your LinkedIn post box.
> 2. When you type `@SWYNEX Technologies`, make sure you select the official **SWYNEX Technologies** company page from the LinkedIn dropdown so it tags them properly.
> 3. Attach either your recorded **demo video** (1-2 minutes) or your favorite screenshot from the `evidence/` folder (such as `01_main_packet_capture_overview.png` or `10_filter_tls_handshake_sni.png`).
> 4. Include the link to your GitHub repository: `https://github.com/ziyakausar07/SWYNEX-Network-Security-Analysis`
> 5. After publishing, copy your LinkedIn post URL and submit it into the SWYNEX internship portal.

---

### 📝 LinkedIn Post Content

```text
🚀 Excited to share that I have completed Task 2: Network Security Analysis as part of my Cyber Security Internship with SWYNEX Technologies! 🛡️

In this project, I used Wireshark to perform a deep-dive defensive packet analysis on real-time network traffic in a controlled workstation environment. 

Here are the key highlights and learnings from this task:
🔍 Protocol Hierarchy Breakdown: Analyzed multi-layer network frames across the OSI model, observing that while IPv6 dominated routing (94.8%), Transport Layer Security (TLS) accounted for over 71% of total network bytes.
🤝 TCP Handshake & State Dissection: Inspected the TCP three-way handshake using the filter `tcp.flags.syn == 1 && tcp.flags.ack == 0`, analyzing initial sequence numbers (ISN), window scaling (WS=256), and Maximum Segment Size (MSS=1460).
🔐 Cryptographic Verification (TLS 1.3): Applied the `tls` display filter to evaluate TLS Client and Server Hello packets, successfully extracting Server Name Indication (SNI) records for Microsoft Telemetry (`mobile.events.data.microsoft.com`) and security endpoints (`api1.reasonsecurity.com`).
📊 Payload Inspection: Used Wireshark’s "Follow TCP Stream" to confirm application data confidentiality, ensuring sensitive payloads are fully encrypted and protected from eavesdropping.
🛡️ Defensive Recommendations: Formulated preventive hardening strategies including zero-trust outbound egress filtering, disabling unnecessary broadcast services (SSDP/mDNS), and securing in-memory database exposures.

A big thank you to SWYNEX Technologies for providing this hands-on, practical learning opportunity to sharpen my defensive security skills!

Check out my full technical report and evidence documentation on GitHub:
👉 https://github.com/ziyakausar07/SWYNEX-Network-Security-Analysis

#SWYNEX #SWYNEXTechnologies #CyberSecurity #Internship #NetworkSecurity #Wireshark #PacketAnalysis #InfoSec #CyberSecurityIntern #DefensiveSecurity #TechCommunity
```

---

### 💡 Quick Checklist Before Submitting to Portal:
- [ ] Tagged `@SWYNEX Technologies` properly.
- [ ] Video or screenshot attached.
- [ ] GitHub link added.
- [ ] Hashtags included: `#SWYNEX #Internship`.
- [ ] Post published in **Public** mode (so reviewers can open it without login issues).
- [ ] Copied the post URL and verified it in an incognito/private tab.
