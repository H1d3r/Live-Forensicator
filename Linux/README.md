<h1 align="center">🛡️ Forensicator (Linux) 🛡️</h1>

<h3 align="center">
Bash-based Incident Response & Live Forensics Toolkit
</h3>

<p align="center">
Lightweight, cross-distro forensic collection and timeline analysis for Linux systems.
</p>

```bash
___________                                .__               __                
\_   _____/__________   ____   ____   _____|__| ____ _____ _/  |_  ___________ 
 |    __)/  _ \_  __ \_/ __ \ /    \ /  ___/  |/ ___\\__  \\   __\/  _ \_  __ \
 |     \(  <_> )  | \/\  ___/|   |  \\___ \|  \  \___ / __ \|  | (  <_> )  | \/
 \___  / \____/|__|    \___  >___|  /____  >__|\___  >____  /__|  \____/|__|   
     \/                    \/     \/     \/        \/     \/                    

                                                                          v4.0.1
```

---

# 🤔 About

**Forensicator (Linux)** is a Bash-based incident response and live forensics tool designed to assist investigators in rapidly collecting and analyzing system artifacts across Linux environments.

It enables:

* Rapid triage of Linux systems
* Collection of key forensic artifacts
* Detection of suspicious persistence mechanisms
* Timeline-based log analysis

Unlike the Windows module, this version focuses on:

* Lightweight execution
* Cross-distribution compatibility
* Investigator-driven analysis (no heavy built-in detection logic)

---

# ⚙️ Key Features

* Cross-distro compatible Bash scripts
* Timeline-based log analysis
* Network capture (PCAP)
* Browser history extraction
* Ransomware extension detection
* Persistence discovery (cron, systemd, init, etc.)
* Structured HTML output

---

# 📦 Optional Dependencies

For additional capabilities:

```bash
avml        → RAM acquisition (https://github.com/microsoft/avml)
sqlite3     → Browser history extraction
```

> Forensicator works without these, but functionality will be limited.

---

# 🔨 Usage

```bash
# Clone repository
git clone https://github.com/Johnng007/Live-Forensicator.git

# Navigate to Linux directory
cd Linux

# Make executable
chmod +x Forensicator.sh

# Execute
./Forensicator.sh <parameters>
```

---

# 🥊 Examples

```bash
# Basic execution
./Forensicator.sh

# Help
./Forensicator.sh --usage

# Capture network traffic (60 seconds)
./Forensicator.sh -p

# Ransomware extension detection
./Forensicator.sh -s

# Web logs (NGINX/Apache)
./Forensicator.sh -w

# Timeline analysis
./Forensicator.sh --timeline '2024-06-01 00:00:00' '2024-06-07 23:59:59'

# Define log files for timeline
./Forensicator.sh --logfiles auth.log,syslog,kern.log

# Define custom log directory
./Forensicator.sh --logdir /custom/log/directory

# Browser history extraction
./Forensicator.sh -b

# RAM capture
./Forensicator.sh -r

# Combined execution
./Forensicator.sh -p -s -w --timeline '2024-06-01 00:00:00' '2024-06-07 23:59:59'

# Unattended mode
./Forensicator.sh -name "Analyst" -case 01123 -title "Incident" -loc "Location" -device HOSTNAME
```

---

# ⚠️ Important Notes

* Run as root for full visibility
* Execution may trigger IDS/IPS alerts
* Outputs are saved as structured HTML reports
* Artifacts are stored locally in the working directory

---

# 🧠 Investigation Capabilities

## 👤 User & Account Data

* Active sessions
* Users with login shells
* SSH authorized keys
* `/etc/passwd`, sudoers

## 💻 System Information

* Kernel & CPU details
* Block devices & USB controllers
* Hardware enumeration

## 🌐 Network Information

* Routing table
* Active connections
* Firewall rules
* Hosts configuration

## ⚙️ Processes & Persistence

* Running processes
* Services & timers
* Cron jobs
* Systemd persistence
* Init scripts

## 🔎 Security Checks

* SetUID binaries
* File capabilities
* Suspicious persistence locations

## 📜 Timeline & Logs

* Auth logs
* System logs
* Custom log timelines
* Web server logs

## 🚀 Extended Features

* Network tracing (PCAP)
* RAM acquisition
* Browser history analysis
* Ransomware extension detection

---

# 📊 Output

Forensicator generates:

* Structured HTML reports
* Organized forensic artifacts
* Timeline-based investigation data

---

# 📸 Screenshots

<details><summary> Terminal</summary>

<img src="https://github.com/Johnng007/Live-Forensicator/blob/main/styles/vendors/images/Forensicator_Output.png?raw=true" />

</details>


<details><summary>HTML Output</summary>

<img src="https://github.com/Johnng007/Live-Forensicator/blob/main/styles/vendors/images/Forensicator_HTML1.png?raw=true" />
<br>
<img src="https://github.com/Johnng007/Live-Forensicator/blob/main/styles/vendors/images/Forensicator_HTML2.png?raw=true" />
<br>
<img src="https://github.com/Johnng007/Live-Forensicator/blob/main/styles/vendors/images/Forensicator_HTML3.png?raw=true" />

</details> 



---

# 🧰 More Tools (Black Widow Toolbox)

* Anteater → Web reconnaissance
  https://github.com/Johnng007/Anteater

* Nessus Pro API → Export scan results
  https://github.com/Johnng007/PowershellNessus

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
