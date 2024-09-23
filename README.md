# NetScanner

```bash
                )           (                   )    )     (     
             ( /(      *   ))\ )  (    (     ( /( ( /(     )\ )  
             )\())(  ` )  /(()/(  )\   )\    )\()))\())(  (()/(  
            ((_)\ )\  ( )(_))(_)|((_|(((_)( ((_)\((_)\ )\  /(_)) 
             _((_|(_)(_(_()|_)) )\___)\ _ )\ _((_)_((_|(_)(_))   
            | \| | __|_   _/ __((/ __(_)_\(_) \| | \| | __| _ \  
            | .` | _|  | | \__ \| (__ / _ \ | .` | .` | _||   /  
            |_|\_|___| |_| |___/ \___/_/ \_\|_|\_|_|\_|___|_|_\
  
````

## Overview

Welcome to **NetScanner**, your go-to tool for effortlessly discovering devices on your local network! Built with Python and Scapy, NetScanner provides a clean and intuitive command-line interface for scanning IP addresses and retrieving essential information about connected devices.

### Why Use NetScanner?

- **User-Friendly**: Designed for both beginners and experienced users, making network scanning simple and efficient.
- **Versatile**: Whether you’re a network administrator, security professional, or just a tech enthusiast, NetScanner meets your needs.
- **Real-Time Results**: Quickly identify devices connected to your network, including their IP and MAC addresses.

## Features

- **Cross-Platform Compatibility**: Use NetScanner on Windows, macOS, and Linux systems.
- **Target Customization**: Easily specify single IPs, ranges, or subnets to scan.
- **Detailed Output**: View a comprehensive list of all detected devices in a clear format.
- **Guided Error Handling**: Friendly error messages help you troubleshoot input issues.

## Installation

### Prerequisites

To run NetScanner, ensure you have:

- **Python 3.x** installed on your machine.
- The **Scapy** library. Install it via pip:

```bash
pip install scapy
```
### Clone the Repository

1. Open your terminal (Command Prompt on Windows, Terminal on macOS/Linux).
2. Clone the repository:

```bash
git clone https://github.com/anishalx/netscanner.git
cd netscanner
```
### Usage
To start scanning, run the script with your desired target IP or IP range:
```bash
python netscanner.py -t {your:IP eg.192.168.1.0/24}
```
### Example Output
<b>Enter IP range</b>
  <p align="center"><img src="https://www.imghost.net/ib/CVPFeSCQEvU5fKS_1727111197.png" width="50%" height="20%"/></p> 
  
### Need Help?
For a detailed list of options and usage instructions, simply run:
```bash
python netscanner.py -h
```
## Operating Systems

NetScanner is compatible with:

- **Windows**: Use Command Prompt or PowerShell.
- **macOS**: Utilize Terminal for seamless execution.
- **Linux**: Run in any terminal emulator of your choice.

## Contributing

We welcome contributions from the community! If you have ideas for improvements or new features, please follow these steps:

1. **Fork the repository**.
2. **Create a new branch** (`git checkout -b feature/YourFeature`).
3. **Make your changes** and commit them (`git commit -m 'Add some feature'`).
4. **Push your branch** (`git push origin feature/YourFeature`).
5. **Open a pull request**.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Special thanks to [Scapy](https://scapy.readthedocs.io/en/latest/) for powering this tool.
- Inspired by various network scanning tools and the open-source community.

