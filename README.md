<h1 align="center">📝 Forensicator 📝</h1>
<h3 align="center"><p><br>WINDOWS(PowerShell) | LINUX(Bash) | MacOS(Bash) </p><br>
  <p>SCRIPTS TO AID LIVE FORENSICS & INCIDENCE RESPONSE </p></h3>
                                               
```bash


___________                                .__               __                
\_   _____/__________   ____   ____   _____|__| ____ _____ _/  |_  ___________ 
 |    __)/  _ \_  __ \_/ __ \ /    \ /  ___/  |/ ___\\__  \\   __\/  _ \_  __ \
 |     \(  <_> )  | \/\  ___/|   |  \\___ \|  \  \___ / __ \|  | (  <_> )  | \/
 \___  / \____/|__|    \___  >___|  /____  >__|\___  >____  /__|  \____/|__|   
     \/                    \/     \/     \/        \/     \/                    

                                                                        v4.1.1        


```


# 🤔 ABOUT

Live Forensicator is part of the Black Widow Toolbox, it aims to assist Forensic Investigators and Incident responders in carrying out a quick live forensic investigation.
<p>It achieves this by gathering different system information for further review for anomalous behavior or unexpected data entry, it also looks out for unusual files or activities and points it out to the investigator.</p>

# 🖳 Forensicator For WINDOWS
<p>The windows version of Forensicator is written in Powershell.</p>
<p> Forensicator for Windows has added the ability to analyze Event Logs, it queries the event logs for certain log IDs that might point to unusual activity or compromise. </p>
<p> Sigma Rules has been added as well. </p>

[Check out Forensicator for Windows](https://github.com/Johnng007/Live-Forensicator/tree/main/Windows)


# 👨‍💻 Forensicator For MacOS
<p>The MacOS version is a shell script.</p>

[Check out Forensicator for MacOS](https://github.com/Johnng007/Live-Forensicator/tree/main/MacOS/)


# 👩‍💻 Forensicator For LINUX
<p>The Linux version is written in Bash.</p>

[Check out Forensicator for Linux](https://github.com/Johnng007/Live-Forensicator/tree/main/Linux)

> #### NOTE: 
> The Bash codes were written for cross-compatibility across Linux distros so therefore efforts were made to use OS native commands while avoiding secondary utilities like `net-tools`.



## ✍ General Notes
* Run the scripts as a privileged user to get value.<br>

* Forensicator Activities may be flagged by IDS or IPS Solutions so take note.<br>

* Forensicator results are output in nice-looking html files with an index file. You can find all extracted Artifacts in the script's working directory.

* <p>Forensicator Stays up to date with Malware signatures, randomware antics, signma rules..etc during script execution Forensicator may attempt to update these files from their sources on the web. </p>

* <p>Feel free to make adjustments in the `config.json` file as required in your investigation</p>

* <p>Sometimes it may be paramount to maintain the integrity of the Artifacts, where lawyers may argue that they might have been compromised on transit to your lab.
  Forensicator can encrypt the Artifact with a unique randomly generated key using the AES algorithm, you can specify this by using the -ENCRYPTED parameter. You can   decrypt it at will anywhere anytime even with another copy of Forensicator (not backward compatible from v4.1.1).
  
  > #### NOTE: 
  > This feature is only currently available in the Windows Module..
  
  </p>

* <p>Forensictor looks out for suspicious activities within the Event Log, it uses several approaches including Sigma Rules.</p>

* <p>Forensictor Matches hashes of executables within the system to malicious hash databases for malware detection, Also browsing history URLs are matched against a list of latest URLs from IOCs for detection.</p>


## Screenshots
<details> <summary> Terminal </summary>

<img width="765" height="1127" alt="image" src="https://github.com/user-attachments/assets/8e49146b-a1e4-4c28-8057-6071903baf75" />

</details>

<details> <summary> Dashboard </summary>
<img src="https://github.com/Johnng007/Live-Forensicator/blob/main/styles/vendors/images/Forensicator_HTML1.png?raw=true" alt="Forensicator"  /> <br>
<img width="1165" height="1037" alt="image" src="https://github.com/user-attachments/assets/7a82d7a4-eac9-4c4c-8b12-193d77ed7640" /> <br>
<img src="https://github.com/Johnng007/Live-Forensicator/blob/main/styles/vendors/images/Forensicator_HTML3.png?raw=true" alt="Forensicator"  /> <br>
<br></br>

</details>

## ✨ ChangeLog
[See Wiki](https://github.com/Johnng007/Live-Forensicator/wiki/Changelog) For full Changelog.
```bash

Windows: v4.1.1 23/03/2026
1. Windows: NEW: Sigma Rules.
2. Windows: NEW: latest hash fetching from abuse.ch .
3. Windows: NEW: Robust Script execution logging.
4. Windows: NEW: Collects Bitlocker key
5. Windows: IMPROVED: Encryption & Decryption functions.
6. Windows: IMPROVED: Browser History extraction & malicious URL check.
7. Windows: IMPROVED: Switched to modern supported commands.

```



## 🤔 MORE TOOLS
Want to check out other Black Widow Tools?
1. [Anteater](https://github.com/Johnng007/Anteater) - A Python-based web reconnaissance tool.
2. [Nessus Pro API](https://github.com/Johnng007/PowershellNessus) - A PowerShell Script to Export and Download Nessus Scan Results via Nessus API. 

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change or add.



## License
[MIT](https://mit.com/licenses/mit/)


<h3 align="left">Support:</h3>
<p><a href="https://ko-fi.com/forensicator"> <img align="left" src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" height="50" width="210" alt="ebuka" /></a></p><br><br>

<h3 align="left">Connect with me:</h3>
<p align="left">
<a href="https://www.linkedin.com/in/ebuka-john-onyejegbu" target="blank"><img align="center" src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/linked-in-alt.svg" alt="ebuka john onyejegbu" height="30" width="40" /></a>
</p>

