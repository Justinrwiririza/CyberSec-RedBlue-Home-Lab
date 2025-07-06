# CyberSec-RedBlue-Home-Lab

## Objective  
The CyberSec RedBlue Home Lab was designed to create a hands-on environment for simulating both offensive (Red Team) and defensive (Blue Team) cybersecurity practices. The lab enables real-time attack simulation, detection, log analysis, and incident response in a safe and isolated setting. This project provides practical exposure to threat hunting, endpoint protection, SIEM integration, and malware analysis—all in one home lab setup.

## Skills Learned  
- Deployment and configuration of multiple virtual machines in a lab environment  
- Hands-on experience with offensive tools and penetration testing using Kali Linux  
- Threat detection and incident analysis using Wazuh SIEM  
- Understanding of Windows internals and malware analysis through Flare VM  
- Network traffic analysis and attack pattern recognition  
- Log correlation and alerting with centralized SIEM  
- Cyber defense strategy planning (Blue Team methodology)  
- Firewall, IDS/IPS, and endpoint protection basics  

## Tools Used  
- **Kali Linux** : Offensive security and penetration testing toolkit  
- **Metasploitable** : Vulnerable VM for attack simulation  
- **Ubuntu Server (Wazuh)** : Open-source SIEM for threat detection and log monitoring  
- **Ubuntu Desktop** : Blue Team workstation for investigation and monitoring  
- **Flare VM** : Malware analysis and Windows reverse engineering environment  
- **VMware Workstation Pro** : Virtualization platform  
- **Wireshark** : Packet capturing and network protocol analysis  
- **Nmap, Metasploit, Netcat, etc.** : Offensive tools for scanning and exploitation  
- **OSSEC/Wazuh Agents** : For log forwarding and endpoint monitoring  

## Steps  

### Ref 1: Lab Network Topology  
_This diagram shows how all virtual machines are networked together. All machines (except Flare VM) are on the NAT adapter to communicate internally. Flare VM is on a Host-Only adapter for isolation._  
![Network Diagram](img/network_diagram.png)

---

### Ref 2: Kali Linux Setup  
_Kali Linux configured with tools like Nmap, Metasploit, and Burp Suite for offensive security exercises._  
![Kali Setup](img/kali_setup.png)

---

### Ref 3: Metasploitable Target  
_Metasploitable intentionally vulnerable VM set up as a Red Team target._  
![Metasploitable](img/metasploitable_running.png)

---

### Ref 4: Wazuh Dashboard  
_Ubuntu Server running Wazuh for log analysis and real-time alerts._  
![Wazuh Dashboard](img/wazuh_dashboard.png)

---

### Ref 5: Flare VM  
_Windows machine configured with Flare VM for malware reverse engineering and Windows-based incident response tools._  
![Flare VM](img/flarevm_analysis.png)

---

### Ref 6: Ubuntu Desktop as Analyst Station  
_Ubuntu Desktop used as Blue Team station to access Wazuh dashboard, Wireshark, and open-source threat intel feeds._  
![Analyst Workstation](img/ubuntu_desktop.png)
