<h1 align="center">🛡️ Forensicator (Windows) 🛡️</h1>

<h3 align="center">
PowerShell-based Incident Response & Live Forensics Toolkit
</h3>

<p align="center">
Advanced event log analysis, detection logic, and forensic artifact collection for Windows systems.
</p>

```bash
___________                                .__               __                
\_   _____/__________   ____   ____   _____|__| ____ _____ _/  |_  ___________ 
 |    __)/  _ \_  __ \_/ __ \ /    \ /  ___/  |/ ___\\__  \\   __\/  _ \_  __ \
 |     \(  <_> )  | \/\  ___/|   |  \\___ \|  \  \___ / __ \|  | (  <_> )  | \/
 \___  / \____/|__|    \___  >___|  /____  >__|\___  >____  /__|  \____/|__|   
     \/                    \/     \/     \/        \/     \/                    

                                                                          v4.1.2
```

---

# 🤔 About

**Forensicator (Windows)** is a PowerShell-based incident response and live forensics tool designed to assist investigators in rapidly collecting and analyzing system artifacts.

It enables:

* Rapid triage of compromised systems
* Detection of suspicious behavior via Event Logs
* Identification of anomalies and indicators of compromise
* Generation of structured, investigation-ready output

Key capabilities include:

* Event Log analysis (targeted Event IDs)
* Sigma rule integration
* Malware hash matching (e.g., abuse.ch feeds)
* Browser history extraction and IOC matching

---

# 📦 Optional Dependencies

Forensicator works out-of-the-box, but additional features are enabled via external tools located in the `Forensicator-Share` folder.

```bash
winpmem_mini_x64_rc2.exe     → RAM acquisition (WinPmem)
etl2pcapng64.exe             → Convert network trace to PCAPNG

```

---

# 📁 Additional Resources

```bash
sqlite3.exe                  → Helps with Browser History extraction
SigmaRuntime.ps1             → Helps in processing Sigma Rules
sigma-rules-precompiled.json → A precompiled updatable Sigma Ruleset easy to parse by the SigmaRuntime.
```

---

# 🔨 Usage

```powershell
# Clone repository
git clone https://github.com/Johnng007/Live-Forensicator.git

# Execute
.\Forensicator.ps1 <parameters>
```

---

# 🥊 Examples

```powershell
# Basic execution
.\Forensicator.ps1

# Version & updates
.\Forensicator.ps1 -VERSION
.\Forensicator.ps1 -UPDATE

# Help
.\Forensicator.ps1 -USAGE

# Event log extraction
.\Forensicator.ps1 -EVTX EVTX

# RAM capture
.\Forensicator.ps1 -RAM RAM

# Network capture (PCAP)
.\Forensicator.ps1 -PCAP PCAP

# Web logs (IIS/Apache)
.\Forensicator.ps1 -WEBLOGS WEBLOGS

# Log4j detection
.\Forensicator.ps1 -LOG4J LOG4J

# Ransomware pattern detection
.\Forensicator.ps1 -RANSOMWARE RANSOMWARE

# Malware hash checking
.\Forensicator.ps1 -HASHCHECK HASHCHECK

# Encrypt artifacts
.\Forensicator.ps1 -ENCRYPTED ENCRYPTED

# Full collection
.\Forensicator.ps1 -EVTX EVTX -RAM RAM -PCAP PCAP -WEBLOGS WEBLOGS

# Unattended mode
.\Forensicator.ps1 -OPERATOR "Name" -CASE 01123 -TITLE "Incident" -LOCATION "Location" -DEVICE HOSTNAME
```

---

# ⚠️ Important Notes

* Run as Administrator for full visibility
* Execution may trigger IDS/IPS alerts
* External threat intelligence may update during runtime
* Configurable via `config.json`

---

# 🔐 Artifact Integrity & Encryption

Artifacts can be encrypted using AES:

* Ensures secure transport
* Preserves evidentiary integrity
* Supports chain-of-custody requirements

```powershell
.\Forensicator.ps1 -ENCRYPTED ENCRYPTED
```

> ⚠️ Not backward compatible before v4.1.1

---

# 🧠 Detection Capabilities

Forensicator detects suspicious activity through:

* Event Log correlation
* Sigma-based detections
* Malicious hash matching
* Browser history IOC analysis

---

# 📊 Data Collected

## 👤 User & Account Information

* Current user
* User accounts & groups
* Logon sessions
* Admin accounts

## 💻 System Information

* Installed programs
* OS & environment details
* Hotfixes
* Defender status

## 🌐 Network Information

* Active connections & processes
* DNS cache
* Firewall rules
* RDP history
* SMB sessions & shares

## ⚙️ Processes & Persistence

* Running processes
* Startup items
* Scheduled tasks
* Services
* Registry persistence

## 📜 Event Log Analysis

* Logon events
* Account changes
* Process execution
* Object access
* Suspicious activities

## 🔎 Additional Checks

* USB devices
* PowerShell history
* Recently created files
* Suspicious executables (AppData, Temp, Downloads)
* BitLocker key extraction

## 🚀 Extended Features

* RAM acquisition
* Network tracing → PCAPNG
* Web server logs (IIS, Tomcat)
* Browser history (all users)
* Ransomware pattern detection
* EVTX export
* Detection Insight into each collected data with Mitre Mapping.

---

# 📸 Screenshots

<details>
<summary>Terminal Output</summary>

<img width="765" height="1127" src="https://github.com/user-attachments/assets/8e49146b-a1e4-4c28-8057-6071903baf75" />

</details>

<details>
<summary>HTML Dashboard</summary>

<img src="https://github.com/Johnng007/Live-Forensicator/blob/main/styles/vendors/images/Forensicator_HTML1.png?raw=true" />
<br>
<img width="1165" height="1037" src="https://github.com/user-attachments/assets/7a82d7a4-eac9-4c4c-8b12-193d77ed7640" />
<br>
<img src="https://github.com/Johnng007/Live-Forensicator/blob/main/styles/vendors/images/Forensicator_HTML3.png?raw=true" />
<br>
<img width="1061" height="933" alt="image" src="https://github.com/user-attachments/assets/3e247456-f406-489f-b240-6acd992c8743" />
<br>
<img width="1060" height="939" alt="image" src="https://github.com/user-attachments/assets/7897da4b-af8c-445c-aac4-0b1cbf76de72" />

</details>

---

# 🤝 Contributing

Pull requests are welcome.
For major changes, please open an issue first to discuss your proposal.

---

# 📄 License

MIT License
https://mit.com/licenses/mit/

---

# ☕ Support

<a href="https://ko-fi.com/forensicator">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" height="50" width="210" />
</a>

---

# 🔗 Connect

<a href="https://www.linkedin.com/in/ebuka-john-onyejegbu">
  LinkedIn
</a>
