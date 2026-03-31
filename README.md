<h1 align="center">🛡️ Forensicator 🛡️</h1>

<h3 align="center">
Cross-platform Incident Response & Live Forensics Toolkit<br>
Windows (PowerShell) | Linux (Bash) | macOS (Shell)
</h3>

<p align="center">
Built for fast, structured, and actionable forensic investigations.
</p>

```bash
___________                                .__               __                
\_   _____/__________   ____   ____   _____|__| ____ _____ _/  |_  ___________ 
 |    __)/  _ \_  __ \_/ __ \ /    \ /  ___/  |/ ___\\__  \\   __\/  _ \_  __ \
 |     \(  <_> )  | \/\  ___/|   |  \\___ \|  \  \___ / __ \|  | (  <_> )  | \/
 \___  / \____/|__|    \___  >___|  /____  >__|\___  >____  /__|  \____/|__|   
     \/                    \/     \/     \/        \/     \/                    

                                                                        v4.1.1
```

---

# 🤔 About

**Forensicator** is a cross-platform incident response and live forensics toolkit, part of the Black Widow Toolbox.

It is designed to help forensic investigators and incident responders rapidly collect, analyze, and interpret system artifacts during live investigations.

Forensicator:

* Collects system and user activity data
* Detects anomalous behavior and suspicious indicators
* Highlights potential compromise or misconfiguration
* Generates structured, investigation-ready HTML reports

---

# ⚙️ Platform Support

## 🖳 Windows (PowerShell)

* Advanced Event Log analysis
* Detection of suspicious activity via known Event IDs
* Integration with Sigma rules
* Malware hash matching (e.g., abuse.ch feeds)
* Browser history analysis with IOC matching
* Optional artifact encryption (AES)

👉 https://github.com/Johnng007/Live-Forensicator/tree/main/Windows

---

## 🍎 macOS (Shell)

* Lightweight artifact collection
* System and user activity inspection

👉 https://github.com/Johnng007/Live-Forensicator/tree/main/MacOS

---

## 🐧 Linux (Bash)

* Cross-distro compatible Bash scripts
* Uses native system utilities (no heavy dependencies)
* Focus on portability and reliability

👉 https://github.com/Johnng007/Live-Forensicator/tree/main/Linux

> ⚠️ Note: Linux scripts are designed to avoid non-native utilities (e.g., `net-tools`) for maximum compatibility.

---

# 🔍 Key Features

* Cross-platform forensic artifact collection
* Detection of suspicious activity and anomalies
* Event Log analysis (Windows)
* Sigma rule integration
* Malware hash and IOC matching
* Structured HTML reporting (with dashboards)
* Optional artifact encryption (Windows module)

---

# 📊 Output

Forensicator generates:

* Clean, structured HTML reports
* Indexed findings for easy navigation
* Extracted artifacts stored locally

This enables fast transition from **data collection → investigation → decision-making**.

---

# ⚠️ Important Notes

* Run scripts with elevated/privileged permissions for best results
* Activity may trigger IDS/IPS alerts — this is expected behavior
* External threat intelligence (hashes, IOCs) may be updated during execution
* Configuration can be customized via `config.json`

---

# 🔐 Artifact Integrity & Encryption

Forensicator supports optional encryption of collected artifacts using AES.

This is useful when:

* Evidence must be transported securely
* Chain-of-custody concerns exist
* Legal integrity of artifacts must be preserved

> ⚠️ Currently available only in the Windows module
> ⚠️ Not backward compatible prior to v4.1.1

---

# 🧠 Detection Capabilities

Forensicator identifies suspicious activity through:

* Event Log analysis
* Sigma-based detections
* Malicious hash matching
* IOC-based URL analysis (browser history)

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

</details>

---

# ✨ Changelog

Full changelog:
👉 https://github.com/Johnng007/Live-Forensicator/wiki/Changelog

```bash
Windows: v4.1.1 (23/03/2026)

- NEW: Sigma rule support
- NEW: Malware hash updates (abuse.ch)
- NEW: Script execution logging
- NEW: BitLocker key collection
- IMPROVED: Encryption/Decryption
- IMPROVED: Browser history & IOC detection
- IMPROVED: Updated to modern commands

Linux v4.1.1 (31/03/2026)

- IMPROVED: Fixed some carriage return errors.
- NEW: Added malicious executable check.
- NEW: Added malicious chell commands check.
```

---

# 🧰 More Tools (Black Widow Toolbox)

* Anteater → Web reconnaissance (Python)
  https://github.com/Johnng007/Anteater

* Nessus Pro API → Export scan results (PowerShell)
  https://github.com/Johnng007/PowershellNessus

---

# 🤝 Contributing

Contributions are welcome.

* Open an issue to discuss major changes
* Submit pull requests with clear descriptions
* Focus on accuracy, clarity, and usability

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
