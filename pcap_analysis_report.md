# **PCAP Analysis Security Report**  
**Date:** 2025-02-01  
**Analyst:** [Your Name]  

---

## **1. Executive Summary**  
This report details the analysis of network traffic captured via Suricata and Zeek logs, focusing on anomalous activities indicating potential reconnaissance and data exfiltration attempts. Key findings include:  
- **Reconnaissance Activity**: An internal host (`10.1.31.101`) queried `checkip.dyndns.org` (MITRE T1590), suggesting network mapping.  
- **Suspicious HTTP/SMTP Traffic**: Outdated user agents, dynamic DNS usage, and unusual data transfer patterns (e.g., HTTP session with 2720B response).  
- **Threat Intelligence**: No malicious IPs detected, but private-to-public IP communications (SMTP, HTTP) require validation.  

**Overall Risk Level**: **Moderate** (5/10).  

---

## **2. Technical Findings**  

### **A. Suricata Events Analysis**  
#### **Event 1: External IP Lookup (HTTP)**  
- **Description**: HTTP GET to `checkip.dyndns.org` from `10.1.31.101` (User-Agent: outdated MSIE 6.0).  
- **Severity**: 5/10  
- **Key Metadata**:  
  - MITRE Tactic: **Reconnaissance (TA0043)**  
  - Technique: **Gather Victim Network Info (T1590)**.  
  - Action: **Allowed** (no blocking).  

#### **Event 2: DNS Query for Dynamic DNS**  
- **Description**: DNS query for `checkip.dyndns.org` from `10.1.31.101` via internal DNS (`10.1.31.1`).  
- **Severity**: 4/10  
- **Correlation**: Part of the same reconnaissance chain as Event 1.  

#### **Event 3: Suspicious SMTP Connection**  
- **Description**: Inbound TCP connection from `208.91.198.143` (port 587) to `10.1.31.101`.  
- **Severity**: 6/10  
- **Concerns**: Potential unauthorized email relaying or malware delivery.  

### **B. Protocol Analysis (Zeek Logs)**  
- **Protocols Observed**:  
  - **HTTP**: Long-lived session (102.96s) with high data transfer (2720B).  
  - **SMTP**: Short but data-heavy (1562B outbound).  
  - **DNS**: Normal queries.  

- **Anomalies**:  
  - Unusual HTTP behavior (possible data exfiltration).  
  - SMTP traffic to public IPs without clear business need.  

---

## **3. Threat Assessment**  
### **MITRE ATT&CK Mapping**  
| **Tactic**          | **Technique**                          | **Example**                          |  
|----------------------|----------------------------------------|---------------------------------------|  
| Reconnaissance       | T1590 (Gather Network Info)           | `checkip.dyndns.org` lookup          |  
| Command & Control    | T1071 (Application Layer Protocol)    | HTTP/SMTP to external IPs            |  

### **IP Reputation**  
- All IPs marked **"clean"** but lack geographic data.  
- Internal IPs (`10.1.31.0/24`) communicating with public IPs (`193.122.6.168`, `208.91.198.143`).  

---

## **4. Recommended Actions**  
### **Immediate Mitigations**  
1. **Isolate & Investigate** `10.1.31.101`:  
   - Scan for malware (outdated user agent suggests legacy vulnerabilities).  
   - Review process logs for suspicious activity.  
2. **Block Dynamic DNS Services**:  
   - Add `checkip.dyndns.org` to DNS blacklist.  
3. **Monitor SMTP Traffic**:  
   - Restrict outbound SMTP to authorized servers.  

### **Long-Term Improvements**  
- **Update Suricata Rules**: Enable blocking for `ET INFO External IP Lookup` (ID: 2021378).  
- **Enable Logging**: Capture full HTTP headers and SMTP payloads for future analysis.  

---

## **5. Visualization Strategy**  
### **Graph-Based Attack Chain**  
- **Tool**: Gephi/Cytoscape.  
- **Nodes**:  
  - **Red**: Suspicious IPs (`193.122.6.168`, `208.91.198.143`).  
  - **Orange**: Internal host (`10.1.31.101`).  
- **Edges**: Labeled with protocols (HTTP/DNS/SMTP)