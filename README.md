# 🧰 ARP CLI Tool

`arpcli.exe` is a command-line utility designed for Windows that allows network administrators (scan - block - unblock) and built to be used in [SafwatX](https://github.com/ZiadSafwat/SafwatX) which is an opensource app , the tool runs on Windows and leverages the powerful [WinPcap](https://www.winpcap.org/) library.

---

## ⚙️ Features

- Scan Network
- Block
- UnBlock
 
---

## 🏗️ Build Instructions

Although `arpcli.exe` is built for **Windows**, it is compiled on **Linux** using the MinGW cross-compiler.

### 🔧 Requirements for building (Linux) 

- `x86_64-w64-mingw32-gcc`
- WinPcap Developer Pack (`WpdPack`)

### 🔧 Runtime Requirements:

- Windows OS

- [WinPcap driver installed](https://www.winpcap.org/install/) 

- Administrator privileges

### 🧪 Build Command
- you need [WinPcap Developer's Pack](https://www.winpcap.org/devel.htm)

```bash
x86_64-w64-mingw32-gcc arpcli.c -o arpcli.exe \
-I/your_path_to_winpcap_dev_pack/Include \
-I/your_path_to_winpcap_dev_pack/Include/pcap \
-L/your_path_to_winpcap_dev_pack/Lib/x64 \
-lwpcap -liphlpapi -lws2_32
```
🖥️ Usage

Copy arpcli.exe to a Windows machine and run it from the command line:
```
ARP CLI Tool - Windows Version
Usage:
  arpcli scan               - Scan network (no need to start first)
  arpcli block <IP>         - Block an IP (add to list)
  arpcli unblock <IP>       - Unblock an IP (remove from list)
  arpcli list               - List blocked IPs
  arpcli start              - Start ARP spoofing blocked IPs
  arpcli stop               - Stop ARP spoofing
  arpcli interfaces         - List available network interfaces
  ```
    ℹ️ Note: Administrative privileges may be required for network interface access.
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

This project is licensed under the MIT License. However, it uses the WinPcap library, which is licensed under the BSD 3-Clause License. Both licenses are included in this repository.
