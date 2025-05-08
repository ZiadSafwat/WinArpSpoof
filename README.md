# 🧰 [WinArpSpoof](https://ziadsafwat.github.io/WinArpSpoof/website/)

`WinArpSpoof.exe` is a command-line utility designed for Windows that allows network administrators (scan - block - unblock) and built to be used in [SafwatX](https://github.com/ZiadSafwat/SafwatX) which is an opensource app , the tool runs on Windows and leverages the powerful [WinPcap](https://www.winpcap.org/) library.

---

## ⚙️ Features

- Scan Network
- Block
- UnBlock
 
When running with `start` command, the tool now automatically:
- 🔒 Sets static ARP entry for your gateway
- 🚫 Blocks dynamic ARP updates on your interface
- 🛡️ Prevents ARP spoofing attacks against your machine
---
## 🖥️ Usage (Choose your system-compatible version)

- first download [Winpcap](https://www.winpcap.org/install/)
- [Download 64-bit version]([./WinArpSpoof.exe](https://github.com/ZiadSafwat/WinArpSpoof/raw/refs/heads/main/WinArpSpoof.exe)  
- [Download 32-bit version](https://github.com/ZiadSafwat/WinArpSpoof/raw/refs/heads/main/WinArpSpoof_32bit.exe)

> ⚠️ **Important:**  
> After downloading, **rename the file to `WinArpSpoof.exe`**, place it on your **Windows machine**, and run it from the **Command Prompt with Administrative privileges**.


ARP CLI Tool - Windows Version
Usage:
- Scan network (no need to start first)
```
WinArpSpoof scan 
```
- Block an IP (add to list)
```
WinArpSpoof block <IP>
```
- Unblock an IP (remove from list)
```  
WinArpSpoof unblock <IP>
```
- List blocked IPs
```
WinArpSpoof list
```
- Start ARP spoofing blocked IPs
```
WinArpSpoof start
```
- Stop ARP spoofing
```
WinArpSpoof stop
```
- List available network interfaces
```
WinArpSpoof interfaces
```

```
    ℹ️ Note: Administrative privileges may be required for network interface access.
```

---
## 🏗️ Build Instructions

Although `WinArpSpoof.exe` is built for **Windows**, it is compiled on **Linux** using the MinGW cross-compiler.

### 🔧 Requirements for building (Linux) 

- `x86_64-w64-mingw32-gcc`
- WinPcap Developer Pack [(`WpdPack`)](https://www.winpcap.org/devel.htm)

### 🧪 Build Command
- you need [WinPcap Developer's Pack](https://www.winpcap.org/devel.htm)
- for 64-bit Windows
```bash
x86_64-w64-mingw32-gcc WinArpSpoof.c -o WinArpSpoof.exe \
-I/your_path_to_winpcap_dev_pack/Include \
-I/your_path_to_winpcap_dev_pack/Include/pcap \
-L/your_path_to_winpcap_dev_pack/Lib/x64 \
-lwpcap -liphlpapi -lws2_32
```
- for 32-bit Windows
```bash
i686-w64-mingw32-gcc WinArpSpoof.c -o WinArpSpoof_32bit.exe \
-I/your_path_to_winpcap_dev_pack/Include \
-I/your_path_to_winpcap_dev_pack/Include/pcap \
-L/your_path_to_winpcap_dev_pack/Lib \
-lwpcap -liphlpapi -lws2_32
```
---
## ⚠️ Ethical and Legal Reminder

ARP spoofing is a Man-in-the-Middle attack and is considered illegal or unauthorized on networks you don't own or manage. Always use this code only in educational labs or networks where you have explicit permission.

---
## My Links 🔗

- 🌐 [My Website](https://waves.pockethost.io/user-profile/3b5wmxh6tierl5h)  


---

Thanks for reading! Stay tuned for more updates! ✨
## 📩 Contact  
📧 **Email:** [Ziadsafwataraby@gmail.com](mailto:Ziadsafwataraby@gmail.com)  
🔗 **Website:** [MyWebsite](https://waves.pockethost.io/user-profile/3b5wmxh6tierl5h)  
🔗 GitHub: @ZiadSafwat
 
## License
📄 Acknowledgments

This project uses WinPcap, developed by:

    NetGroup, Politecnico di Torino (Italy)

    CACE Technologies, Davis (California)

🪪 License

This project is licensed under the MIT License. However, it uses the WinPcap library, which is licensed under the BSD 3-Clause License.
