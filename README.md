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

### Step 1: Lab Network Topology  
_This diagram shows how all virtual machines are networked together. All machines (except Flare VM) are on the NAT adapter to communicate internally. Flare VM is on a Host-Only adapter for isolation._  
<img src="https://i.imgur.com/TQM5rDj.png" alt="CyberSec Lab Diagram" width="600"/>
## Kali Linux (Red Team) Dashboad
<img src="https://i.imgur.com/pW9shD2.png" alt="CyberSec Lab Diagram 6" width="600"/>

## Metasploite Dashboad
<img src="https://i.imgur.com/PL9bwpt.png" alt="CyberSec Lab Diagram 7" width="600"/>

## Ubuntu Desktop Dashboad
Ubuntu Desktop used as Blue Team station to access Wazuh dashboard, Wireshark, and open-source threat intel feeds
<img src="https://i.imgur.com/0tA8IWB.png" alt="CyberSec Lab Diagram 8" width="600"/>

## Wazuh Dashboad
Ubuntu Server running Wazuh for log analysis and real-time alerts.
<img src="https://i.imgur.com/shXSmzv.png" alt="CyberSec Lab Diagram 9" width="600"/>

## Flare vm Dashboad
Windows machine configured with Flare VM for malware reverse engineering and Windows-based incident response tools.
<img src="https://i.imgur.com/4AUEqxL.png" alt="CyberSec Lab Diagram 5" width="600"/>

### Step 2: Virtual Machine Setup & Configuration  
In this phase, I installed and configured all virtual machines listed in the network topology. Each VM was assigned to its appropriate role and network adapter, with static IPs set where needed. Tools and agents were installed for threat simulation, detection, and analysis.  
<table border="1" cellpadding="8" cellspacing="0">
  <thead>
    <tr>
      <th>VM Name</th>
      <th>OS/Tool</th>
      <th>Role</th>
      <th>Network</th>
      <th>Key Setup Items</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>kali-attacker</td>
      <td>Kali Linux</td>
      <td>Red Team Attacker</td>
      <td>NAT</td>
      <td>Nmap, Metasploit, Wireshark, Burp Suite, Gobuster</td>
    </tr>
    <tr>
      <td>metasploitable-victim</td>
      <td>Metasploitable</td>
      <td>Vulnerable Target</td>
      <td>NAT</td>
      <td>Default credentials, no hardening</td>
    </tr>
    <tr>
      <td>ubuntu-wazuh-server</td>
      <td>Ubuntu Server + Wazuh</td>
      <td>SIEM & Host Monitoring</td>
      <td>NAT</td>
      <td>Wazuh Manager, Filebeat, Suricata, Elasticsearch</td>
    </tr>
    <tr>
      <td>ubuntu-desktop</td>
      <td>Ubuntu Desktop</td>
      <td>Blue Team Workstation</td>
      <td>NAT</td>
      <td>Wazuh Agent, OSSEC Alerts, Wireshark</td>
    </tr>
    <tr>
      <td>flare-vm</td>
      <td>Flare VM (Windows)</td>
      <td>Malware Analysis & Reverse Engineering</td>
      <td>Host-Only</td>
      <td>IDA Free, PE Studio, x64dbg, dnSpy, Wireshark</td>
    </tr>
  </tbody>
</table>

### Step 3: Network Validation
Before launching anything, I made sure all machines were properly connected based on their network configurations (NAT, Host-Only, etc.).
I used ping, ifconfig, and ip a from Kali to confirm communication with Metasploitable and Wazuh. Smooth and responsive everything was talking perfectly. 
"type in kali linux ping followed by Metasploitable or wazuh to see if communication is perfect" 

### Step 4: Snapshot All VMs
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
