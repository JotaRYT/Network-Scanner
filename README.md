# Network Scanner

A Python-based network scanning tool that discovers devices on a local network and performs port scanning.

## Features

- Network device discovery using ARP scanning
- Port scanning for common services
- Hostname resolution for discovered devices
- Support for custom IP ranges and port lists

## Requirements

- Python 3.x
- Scapy library
- Root/Administrator privileges (for ARP scanning)

## Installation

1. Clone this repository:

```sh
git clone https://github.com/JotaRYT/network-scanner.git
cd network-scanner/src
```

2. Create a virtual environment:

```py
python -m venv myenv
source myenv/bin/activate  # On Windows: myenv\Scripts\activate
```

3. Install required packages:

```py
pip install scapy
```

or

```py
pip3 install scapy
```

## Configuration

1. Modify IP_RANGE in the script to match your network (default: "192.168.1.0/24")
2. Customize PORTS_TO_SCAN list to scan different ports

## Usage

Run the script with root/admin privileges:

```zsh
sudo python network_scanner.py
```

## Security Notice

This tool should only be used on networks you own or have explicit permission to scan. Unauthorized scanning may be illegal.

## License

MIT License - See [LICENSE](LICENSE) file for details

## Author

JotaRYT a.k.a BleckWolf25
