import logging
from scapy.all import IP,DNSRR,sniff

logger=logging.getLogger(__name__)
def dns_amplification_detector(packet):
    logger.info("DNS amplification detector started.")
    if packet.haslayer(IP) and packet.haslayer(DNSRR):
        if len(packet) > 512:
            src_ip=packet[IP].src
            logger.info(f"DNS amplification attack detected from {src_ip}.")
sniff(filter="udp port 53",prn=dns_amplification_detector,store=0,timeout=10)
