# Netwatch-IDS
This Intrusion Detection System (IDS) monitors network traffic and detects various types of network attacks, including ARP poisoning, DNS amplification, DNS spoofing, ping of death, port scan, and SYN flood attacks.
## Prerequisites

- Python 3.x
- `scapy` library
- Administrator/root privileges (required for capturing network packets)

## Setup

1. **Install Python 3.x**:
   Make sure you have Python 3.x installed on your system. You can download it from [python.org](https://www.python.org/).

2. **Install `scapy`**:
   Install the `scapy` library using `pip`:
   ```sh
   pip install scapy

## Running Netwatch-IDS 

1. Ensure Administrator/Root Privileges:
   To capture network packets, you need to run the IDS with administrator/root privileges.

2. Run the IDS:  
   On Unix-based systems:
   ```sh
   sudo python main.py
   ```
   On Windows (run as Administrator):
   ```sh
   python main.py      
   ```

3. Check the Logs:
   The IDS will log its activities in the ids.log file. The activities consist of detections by the various signature based detectors.

   
## Detectors
ARP Poisoning Detector  
Monitors ARP traffic to detect potential ARP spoofing attacks.

DNS Amplification Detector  
Monitors DNS traffic to detect DNS amplification attacks.

DNS Spoof Detector  
Monitors DNS responses to detect potential DNS spoofing attacks.

Ping of Death Detector  
Monitors ICMP traffic to detect large ICMP packets that could indicate a ping of death attack.

Port Scan Detector  
Monitors TCP SYN packets to detect potential port scanning activities.

SYN Flood Detector  
Monitors TCP SYN packets to detect SYN flood attacks.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.
