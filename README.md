# 🛠️ Adobe Updater Red Team Simulation

This project simulates a realistic Adobe Acrobat Updater using a `.hta` payload to demonstrate social engineering, stealthy execution, and persistence techniques. It was designed for red team demonstrations, detection engineering, and adversary emulation.

## 📌 Key Features

- 🎭 **Fake Adobe UI** — Mimics the real updater using HTML, CSS, and HTA scripting
- 💀 **PowerShell Reverse Shell** — Initiates a TCP callback to a remote listener
- 🧠 **Persistence via Registry** — Auto-runs on user login via `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- 🎬 **Loading Animation & Progress Bar** — Visual deception to appear like a real installation
- 💻 **LOLBAS Execution** — Delivered via `wscript.exe` using only built-in Windows tools

## 🔧 How It Works

1. The `.hta` file is executed using `wscript.exe`
2. A fake Adobe-style popup prompts the user to “install critical updates”
3. On confirmation, the HTA:
   - Spawns a hidden PowerShell reverse shell to a remote Kali listener
   - Writes itself to the registry for persistence
4. Meanwhile, a UI simulates an Adobe install (loading dots + red progress bar)
5. Once complete, the window auto-closes

## 🛡️ Detection & Mitigation Tips

> *Blue teamers, here’s what to watch for:*

- Look for suspicious child processes of `wscript.exe`
- Monitor registry keys in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Detect hidden PowerShell or encoded payloads with command-line logging
- Use Sysmon + Defender ASR rules to block script-based persistence

## 🧪 Lab Setup Notes

- 🧱 Windows 10 VM (Defender ON)
- 🧑‍💻 Kali Linux listener
- HTA executed via `wscript.exe` or double-click

### Example Netcat Listener:
```bash
nc -lvnp 443
