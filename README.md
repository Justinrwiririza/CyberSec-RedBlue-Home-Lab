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
## Kali Linux (Red Team) Dashboard
Simulate attacker behavior

<img src="https://i.imgur.com/pW9shD2.png" alt="CyberSec Lab Diagram 6" width="600"/>

## Metasploite Dashboard
Provide an exploitable target

<img src="https://i.imgur.com/PL9bwpt.png" alt="CyberSec Lab Diagram 7" width="600"/>

## Ubuntu Desktop Dashboard
Ubuntu Desktop used as Blue Team station to access Wazuh dashboard, Wireshark, and open-source threat intel feeds

<img src="https://i.imgur.com/0tA8IWB.png" alt="CyberSec Lab Diagram 8" width="600"/>

## Wazuh Dashboard
Monitor activity, raise alerts, and act as the Blue Team's SIEM
<img src="https://i.imgur.com/shXSmzv.png" alt="CyberSec Lab Diagram 9" width="600"/>

## Flare vm Dashboard
Isolated malware analysis and reverse engineering

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

From Kali, run: 

ping "IP of Metasploitable"

ping "IP of Wazuh server"


### Step 4: Snapshot All VMs
Before diving into attack scenarios, I took snapshots of each VM. It's like creating a "checkpoint" if anything broke during testing (and some things did!), 
I could easily roll back.

### Ref 5: Red Team Offensive Testing 
Reconnaissance

Run:

- nmap -sV to scan Metasploitable to discover software and version on metasploite
<img src="https://i.imgur.com/GMRBDvG.png" alt="CyberSec Lab Diagram" width="600"/>
After Nmap scan, the Metasploitable machine revealed 23 open ports, exposing a wide attack surface. Key vulnerable services include vsftpd 2.3.4 (with a known backdoor), Apache 2.2.8, and Samba smbd, which are outdated and exploitable. The scan also identified multiple remote access services like Telnet, SSH, and VNC, increasing the risk of brute-force or misconfiguration attacks. Additionally, services like MySQL, PostgreSQL, and Java RMI were found open, which could be exploited through weak credentials or serialization vulnerabilities. Notably, a bindshell on port 1524 suggests an already compromised backdoor providing root shell access.


- gobuster to discover hidden web directories.
<img src="https://i.imgur.com/CS0YyCn.png" alt="CyberSec Lab Diagram" width="600"/>

The Gobuster scan metasploitable IP revealed several interesting directories and files that could be leveraged during further analysis. It identified potentially sensitive files like .htaccess, .htpasswd, and .hta, though they returned 403 Forbidden, indicating restricted access. Accessible directories such as phpMyAdmin, test, dav and twiki suggest misconfigurations or outdated web applications that may be vulnerable. Notably, /phpinfo.php and /phpinfo are publicly exposed, potentially leaking system and PHP configuration details useful for crafting exploits. These findings highlight weak access controls and outdated components in the web environment, ideal for web-based attack vectors.

After conducting thorough reconnaissance using nmap and gobuster, I identified multiple exposed services and web directories on the Metasploitable machine. Based on the findings, I selected three high-value exploitation targets to demonstrate real-world attack techniques in a controlled lab environment:

- vsftpd 2.3.4 – A vulnerable FTP service with a known backdoor that allows unauthenticated remote shell access.

- phpMyAdmin & phpinfo.php – Misconfigured web applications that expose system information and potentially allow brute-force or file
  upload attacks.     

- TWiki Web Application – An outdated wiki platform with known remote code execution vulnerabilities.

### Exploitation 1: vsftpd 2.3.4 Backdoor
After identifying vsftpd 2.3.4 running on port 21/tcp, I confirmed that it was a vulnerable version known to contain a built-in backdoor (CVE-2011-2523). This backdoor is triggered when a username with a smiley face  is submitted during the FTP login process, causing the service to spawn a shell on a high-numbered port.

To exploit this, I used Metasploit on the Kali Linux attack machine:

<img src="https://imgur.com/EqX7a3o.png" alt="CyberSec Lab Diagram" width="600"/>
I loaded the vsftpd_234_backdoor exploit module

<img src="https://imgur.com/vdNKMKC.png" alt="CyberSec Lab Diagram" width="600"/>
Set the target IP and confirmed the default port

<img src="https://imgur.com/QPSvuTc.png" alt="CyberSec Lab Diagram" width="600"/>
Executed the exploit

<img src="https://imgur.com/nN2QNmS.png" alt="CyberSec Lab Diagram" width="600"/>
Metasploit successfully established a reverse shell connection to the Metasploitable machine, granting me unauthenticated root access to the system. This demonstrated how an outdated service with a known vulnerability can be fully compromised with minimal effort, reinforcing the importance of service hardening and patch management.

### Impact & Mitigation
### Impact 
This is what happens after successful exploitation:
- Privilege level gained.
- System control level.
- Potential risks if used in real-world scenarios

### Example:
Exploitation provides an unauthenticated root shell, allowing full control of the system. Attackers can install malware, exfiltrate data, or pivot to other systems.

### Mitigation
We can fix or reduce the risk by:
- Upgrade or patch the service
- Apply firewall rules.
- Disable unnecessary services.

### Example:
- Upgrade to the latest version of vsftpd.
- If FTP is not needed, disable the service (systemctl disable vsftpd)
- Restrict access using firewall rules.
- Enable SFTP or FTPS for secure file transfers.
### Exploitation 2: phpMyAdmin Misconfiguration
- Objective: Exploit a misconfigured phpMyAdmin instance on the target machine to gain remote code execution and escalate privileges.
- Goal: Gain access to the database and potentially escalate to system-level compromise.
- Tools: Hydra (for brute force), Metasploit.
#### Reconnaissance
- Identified Apache service running on port 80 via Nmap.
<img src="https://i.imgur.com/GMRBDvG.png" alt="CyberSec Lab Diagram" width="600"/>
  
- Discovered `/phpmyadmin` directory using Gobuster.
- Identified the target application phpMyAdmin running on the server
- Discovered the URL endpoint: http://Target-IP/phpmyadmin.
  
<img src="https://i.imgur.com/CS0YyCn.png" alt="CyberSec Lab Diagram" width="600"/>

### Scanning and Enumeration
- Confirmed phpMyAdmin is accessible.
- Identified possible login weaknesses (default credentials).

<img src="https://imgur.com/ofiXutY.png" alt="CyberSec Lab Diagram" width="600"/>

### Exploitation
- Logged in using default credentials (root with no password).
- Verified full access to the database.

<img src="https://imgur.com/E5PDjE6.png" alt="CyberSec Lab Diagram" width="600"/>

- Confirm that you can execute queries without restrictions.
  
<img src="https://imgur.com/KM3liRm.png" alt="CyberSec Lab Diagram" width="600"/>

Exploitation refers to the phase in an attack where an attacker actively uses a vulnerability or weakness to gain unauthorized access to a system, application, or service. This happens after reconnaissance and scanning but before post-exploitation.

### Impact of Exploitation
### 1. Initial System Compromise
Attacker gains control of the target system or application.
### 2. Unauthorized Data Access
Sensitive data (credentials, PII, financial info) can be read or modified.
### 3. Privilege Escalation Potential
Exploitation can lead to root/admin privileges.
### 4. Deployment of Malware or Backdoors
Web shells, reverse shells, and persistent scripts can be placed on the server.
### 5. Network Entry Point
The compromised system becomes a pivot point to attack other assets.

### Mitigation of Exploitation

### 1. Input Validation & Sanitization
- Validate user inputs on server side.
- Use parameterized queries (Prepared Statements) to prevent SQL Injection.
### 2. Principle of Least Privilege
- Database users should not have file write permissions (SELECT INTO OUTFILE should be disabled).
- Web server accounts should not run as root.
### 3. Apply Security Patches
Keep web apps, databases, and OS up to date with patches.
### 4. Web Application Firewall (WAF)
Block malicious payloads and SQL Injection attempts.
### 5. Enable Logging & Monitoring
Monitor web server logs for suspicious requests and unusual patterns
### 6. Regular Security Testing
- Perform vulnerability assessments and penetration testing.
- Use automated tools to detect misconfigurations.

### Post-Exploitation – Gaining Remote Command Execution via Web Shell
### Step 1: Upload a PHP Web Shell via SQL query

After confirming unrestricted SQL query execution in phpMyAdmin, 
I used the (SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';) query to upload a simple PHP web shell.

<img src="https://imgur.com/c8iL3gF.png" alt="CyberSec Lab Diagram" width="600"/>
Purpose: This creates a file shell.php in the web root directory that allow remote command execution through HTTP requests.

### Step 2: Executed system commands through the web shell.
Access the uploaded shell in a browser → http://<Target-IP>/shell.php?cmd=whoami → Check current user privileges

<img src="https://imgur.com/pJW9rmC.png" alt="CyberSec Lab Diagram" width="600"/>

Access the uploaded shell in a browser → http://<Target-IP>/shell.php?cmd=uname -a → Get system information

<img src="https://imgur.com/j1yGgom.png" alt="CyberSec Lab Diagram" width="600"/>

Access the uploaded shell in a browser → http://<Target-IP>/shell.php?cmd=id → Display user and group IDs

<img src="https://imgur.com/Lx6BVsk.png" alt="CyberSec Lab Diagram" width="600"/>

Post-Exploitation refers to the phase after an attacker has successfully gained access to a system. The focus during this stage is on maintaining access, escalating privileges, gathering sensitive information, pivoting within the network, and deploying additional tools or persistence mechanisms. This stage often determines the overall impact of the attack.

### Impact

### 1. Remote Code Execution
The attacker can execute arbitrary system commands remotely with the same privileges as the web server user (often www-data or apache).
### 2. Privilege Escalation
From the web shell, attackers can attempt local privilege escalation exploits to gain root/system access.
### 3. Full System Compromise
If the web server user has high privileges or the attacker escalates, the entire system is compromised.
### 4. Pivoting Inside the Network
Once a shell is obtained, attackers can scan the internal network and attack other systems.
### 5. Data Theft or Tampering
Sensitive data (databases, configs, credentials) can be accessed, modified, or exfiltrated.
### 6. Persistence
Attackers can install backdoors, cron jobs, or additional malware to maintain access.

### Mitigation
### 1. Disable Dangerous PHP Functions
Disable system(), exec(), shell_exec(), and similar functions in php.ini.
### 2. Restrict File Upload & Database Features
- Validate and sanitize all file uploads (allow only safe file types).
- Disable SELECT INTO OUTFILE in MySQL to prevent arbitrary file writes.
### 3. Principle of Least Privilege
- Run the web server under a non-root user with limited permissions.
- Ensure database users have minimal privileges.
### 4. Apply Web Application Security Controls
- Use a Web Application Firewall (WAF) to detect/block malicious requests.
- Implement proper input validation to prevent SQL Injection
### 5. Enable Logging & Monitoring
- Monitor HTTP logs for suspicious queries like ?cmd=.
- Use IDS/IPS or SIEM solutions to detect abnormal activity.
### 6. Patch & Harden
- Keep web applications and servers updated.
- Disable unused services and enforce strong authentication.
### 7. Incident Response Readiness
- Regularly scan for unexpected files (like shell.php).
- Use integrity checks (e.g., Wazuh...).


### Persistence
steps and screenshot coming soon

What is it?
persistence refers to the attacker establishing a reliable presence on a compromised system or network. Persistence means maintaining that access over time even after reboots, patching, or other remediation efforts. Common techniques used are:
- Uploading and running web shells (like your PHP shell)
- Creating backdoor user accounts
- Installing scheduled tasks (cron jobs)
- Modifying startup scripts or services
- Implanting malicious binaries or scripts

### Impact

- Continuous Access: Attackers can maintain long-term access without repeated exploitation.
- Privilege Escalation: Persistence mechanisms can facilitate escalation to higher privileges.
- Data Exfiltration: Allows stealthy extraction of sensitive data over time.
- Lateral Movement: Enables attackers to pivot inside the network to compromise more assets.
- Difficult Detection: Persistent backdoors often evade detection by antivirus or monitoring tools.
- System Stability Risks: Malicious persistence can cause system instability or crashes.

### Mitigation

- Restrict File Uploads: Disable or tightly control file upload functionalities on web apps.
- Harden Web Servers: Restrict web server permissions to prevent writing/executing unauthorized files.
- Monitor Changes: Use file integrity monitoring to detect unauthorized file changes.
- Disable Dangerous SQL Functions: Disable SELECT INTO OUTFILE or similar risky database features.
- Regular Audits: Conduct frequent audits of user accounts, scheduled tasks, and startup scripts
- Endpoint Detection: Deploy EDR solutions that detect and alert on suspicious persistence behaviors.
- Apply Patching: Keep software and OS up to date to close known vulnerabilities.
- Implement Network Segmentation: Limit the attacker’s ability to move laterally.
- Incident Response Plan: Have clear procedures to identify and remove persistence mechanisms.

