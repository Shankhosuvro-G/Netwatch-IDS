import logging
from scapy.all import IP,DNSRR,sniff

logger=logging.getLogger(__name__)
DNS_address=["8.8.8.8","8.8.4.4"]
def detect_dns_spoofing(packet):
    logger.info("DNS spoof detector started.")
    if packet.haslayer(IP) and packet.haslayer(DNSRR):
        if packet[IP].src not in DNS_address:
            logger.info(f"DNS spoofing detected from {packet[IP].src}.")
sniff(filter="udp port 53",prn=detect_dns_spoofing,store=0,timeout=10)                        