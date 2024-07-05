import logging
from scapy.all import IP,ICMP,sniff

logger=logging.getLogger(__name__)
def detect_POD(packet):
    logger.info("Ping of death detector started.")
    if packet.haslayer(IP) and packet.haslayer(ICMP):
        if len(packet(IP)>65535):
            logger.info(f"Ping of death has been detected from {packet[IP].src}.")
sniff(filter="icmp",prn=detect_POD, store=0,timeout=10)            