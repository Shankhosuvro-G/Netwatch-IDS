import logging
from scapy.all import IP,TCP,sniff
from collections import defaultdict

logger=logging.getLogger(__name__)

port_scan_threshold=10
scan_attempts=defaultdict(list)

def port_scan_detector(packet):
    logger.info("Port scan detector started.")
    if packet.haslayer(IP):    
        if packet.haslayer(TCP):
            src_ip=packet[IP].src
            current_time=packet.time
            scan_attempts[src_ip].append(current_time)

    if len(scan_attempts) > port_scan_threshold:
        logger.info(f"Port scan detected from {src_ip}.")
sniff(filter="tcp",prn=port_scan_detector,store=0,timeout=10)        